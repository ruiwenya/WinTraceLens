// Package commandchain conservatively extracts persistence targets from command
// strings. It never evaluates scripts or starts a referenced program.
package commandchain

import (
	"encoding/base64"
	"encoding/binary"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
)

const maxCommandBytes = 64 * 1024

type Target struct {
	Raw          string `json:"raw"`
	Path         string `json:"path"`
	Kind         string `json:"kind"`
	Via          string `json:"via"`
	FileStatus   string `json:"fileStatus"`
	CheckError   string `json:"checkError,omitempty"`
	MD5          string `json:"md5,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	HashError    string `json:"hashError,omitempty"`
	Signature    string `json:"signature,omitempty"`
	SignatureMsg string `json:"signatureMsg,omitempty"`
	Size         int64  `json:"size"`
	Created      string `json:"created,omitempty"`
	Modified     string `json:"modified,omitempty"`
}

type Chain struct {
	Launcher         Target   `json:"launcher"`
	Payloads         []Target `json:"payloads"`
	WorkingDirectory string   `json:"workingDirectory"`
	Asynchronous     bool     `json:"asynchronous"`
	Interpreters     []string `json:"interpreters"`
	Warnings         []string `json:"warnings"`
	Encoded          bool     `json:"encoded"`
}

type Options struct {
	WorkingDirectory string
	Expand           func(string) string
	Resolve          func(value, workingDirectory string) string
}

func Clone(chain *Chain) *Chain {
	if chain == nil {
		return nil
	}
	copy := *chain
	copy.Payloads = append([]Target(nil), chain.Payloads...)
	copy.Interpreters = append([]string(nil), chain.Interpreters...)
	copy.Warnings = append([]string(nil), chain.Warnings...)
	return &copy
}

// Primary returns a concrete referenced file before the interpreter, while
// preserving unresolved/remote references separately in the complete chain.
func Primary(chain *Chain) Target {
	if chain == nil {
		return Target{}
	}
	for _, target := range chain.Payloads {
		if target.Kind == "file" && !IsInterpreter(target.Path) {
			return target
		}
	}
	return chain.Launcher
}

type token struct {
	value      string
	start, end int
	quoted     bool
}
type parser struct {
	chain Chain
	opts  Options
	seen  map[string]bool
}

var embeddedTarget = regexp.MustCompile(`(?i)https?://[^\s"'<>;|]+|(?:[a-z]:\\|%[a-z_0-9]+%\\|\$env:[a-z_0-9]+\\)[^\r\n"'<>|;]*?\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf|sys)(?:\b)`)

func Parse(command string, opts Options) Chain {
	p := parser{opts: opts, seen: make(map[string]bool)}
	p.chain.WorkingDirectory = opts.WorkingDirectory
	p.parse(command, 0, "入口", true)
	return p.chain
}

func (p *parser) warn(value string) {
	for _, old := range p.chain.Warnings {
		if old == value {
			return
		}
	}
	p.chain.Warnings = append(p.chain.Warnings, value)
}

func (p *parser) target(value, via string, launcher bool) {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" {
		return
	}
	if p.opts.Expand != nil {
		value = p.opts.Expand(value)
	}
	t := Target{Raw: value, Via: via, Kind: "file", FileStatus: "未检查"}
	if strings.HasPrefix(strings.ToLower(value), "http://") || strings.HasPrefix(strings.ToLower(value), "https://") {
		t.Kind, t.Path, t.FileStatus = "url", value, "远程目标（未连接）"
	} else if p.opts.Resolve != nil {
		t.Path = p.opts.Resolve(value, p.chain.WorkingDirectory)
	} else {
		t.Path = value
	}
	if t.Path == "" || strings.ContainsAny(t.Path, "%$!") {
		t.Kind, t.FileStatus = "unresolved", "未解析（缺少运行上下文）"
		p.warn("相对路径、变量或动态命令无法静态确定；当前结果不代表完整执行链")
	}
	if launcher {
		p.chain.Launcher = t
		return
	}
	key := strings.ToLower(t.Path + "|" + t.Raw)
	if !p.seen[key] && len(p.chain.Payloads) < 32 {
		p.seen[key] = true
		p.chain.Payloads = append(p.chain.Payloads, t)
	}
	if len(p.chain.Payloads) >= 32 {
		p.warn("执行链达到 32 个目标上限")
	}
}

// cmd.exe does not use backslash to escape quotes. Keep source spans so nested
// command tails can be parsed without rebuilding or executing their arguments.
func lex(value string) []token {
	var out []token
	for i := 0; i < len(value); {
		for i < len(value) && strings.ContainsRune(" \t\r\n", rune(value[i])) {
			i++
		}
		if i == len(value) {
			break
		}
		t := token{start: i}
		var b strings.Builder
		var quote byte
		for i < len(value) {
			c := value[i]
			if c == '^' && quote == 0 && i+1 < len(value) {
				i++
				b.WriteByte(value[i])
				i++
				continue
			}
			if c == '"' || c == '\'' {
				if quote == 0 {
					quote = c
					t.quoted = true
					i++
					continue
				}
				if quote == c {
					quote = 0
					i++
					continue
				}
			}
			if quote == 0 && strings.ContainsRune(" \t\r\n", rune(c)) {
				break
			}
			b.WriteByte(c)
			i++
		}
		t.end, t.value = i, b.String()
		out = append(out, t)
	}
	return out
}

func splitCommands(value string) []string {
	var parts []string
	start := 0
	var quote byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '^' && quote == 0 {
			i++
			continue
		}
		if c == '"' || c == '\'' {
			if quote == 0 {
				quote = c
			} else if quote == c {
				quote = 0
			}
			continue
		}
		if quote == 0 && (c == '&' || c == '|' || c == ';' || c == '\n') {
			parts = append(parts, strings.TrimSpace(value[start:i]))
			for i+1 < len(value) && value[i+1] == c {
				i++
			}
			start = i + 1
		}
	}
	return append(parts, strings.TrimSpace(value[start:]))
}

func (p *parser) parse(command string, depth int, via string, launcher bool) {
	if depth > 6 || len(command) > maxCommandBytes {
		p.warn("命令超过静态解析深度或长度上限")
		return
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return
	}
	if p.opts.Expand != nil {
		command = p.opts.Expand(command)
	}
	ts := lex(command)
	if len(ts) == 0 {
		return
	}
	name := base(ts[0].value)
	if name == "cd" || name == "chdir" || name == "set-location" {
		idx := 1
		if idx < len(ts) && strings.EqualFold(ts[idx].value, "/d") {
			idx++
		}
		if idx < len(ts) {
			path := ts[idx].value
			if p.opts.Resolve != nil {
				path = p.opts.Resolve(path, p.chain.WorkingDirectory)
			}
			if path != "" {
				p.chain.WorkingDirectory = path
			} else {
				p.warn("工作目录无法静态确定")
			}
		}
		return
	}
	if name == "start" || name == "start-process" {
		idx, wait := 1, false
		titleConsumed := false
		for idx < len(ts) {
			if name == "start" && !titleConsumed && ts[idx].quoted {
				titleConsumed = true
				idx++
				continue
			}
			arg := strings.ToLower(ts[idx].value)
			if arg == "/wait" || arg == "-wait" {
				wait = true
				idx++
				continue
			}
			if arg == "/d" || arg == "-workingdirectory" {
				idx++
				if idx < len(ts) {
					path := ts[idx].value
					if p.opts.Resolve != nil {
						path = p.opts.Resolve(path, p.chain.WorkingDirectory)
					}
					if path != "" {
						p.chain.WorkingDirectory = path
					}
					idx++
				}
				continue
			}
			if arg == "-filepath" {
				idx++
				break
			}
			if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "-") {
				idx++
				continue
			}
			break
		}
		p.chain.Asynchronous = p.chain.Asynchronous || !wait
		if idx < len(ts) {
			p.parse(command[ts[idx].start:], depth+1, name, false)
		} else {
			p.warn("start 未能解析出启动目标")
		}
		return
	}
	if name == "call" && len(ts) > 1 {
		p.parse(command[ts[1].start:], depth+1, "cmd call", false)
		return
	}
	if name == "echo" || name == "exit" || name == "rem" || name == "set" {
		return
	}
	if name == "if" || name == "for" {
		p.warn("cmd 条件或循环未求值，仅保留其中的文件字面量引用")
		for _, value := range embeddedTarget.FindAllString(command, 32) {
			p.target(value, "条件/循环字面量引用（需复核用途）", false)
		}
		return
	}
	first := ts[0].value
	if !ts[0].quoted && strings.Contains(first, `:\`) && !isFile(first) {
		for i := 1; i < len(ts) && i < 16; i++ {
			first += " " + ts[i].value
			if isFile(first) {
				p.warn("未加引号的含空格路径仅按预期目标提取；实际启动文件还受 Windows 搜索规则影响")
				ts = append([]token{{value: first, start: 0, end: ts[i].end}}, ts[i+1:]...)
				name = base(first)
				break
			}
		}
	}
	p.target(ts[0].value, via, launcher)
	if IsInterpreter(name) {
		found := false
		for _, old := range p.chain.Interpreters {
			if old == name {
				found = true
			}
		}
		if !found {
			p.chain.Interpreters = append(p.chain.Interpreters, name)
		}
	}
	switch name {
	case "cmd":
		for i := 1; i < len(ts); i++ {
			arg := strings.ToLower(ts[i].value)
			if arg == "/c" || arg == "/k" {
				tail := strings.TrimSpace(command[ts[i].end:])
				tailTokens := lex(tail)
				if len(tail) > 1 && tail[0] == '"' && tail[len(tail)-1] == '"' && (len(tailTokens) == 1 || strings.HasPrefix(tail, `""`)) {
					tail = tail[1 : len(tail)-1]
				}
				for _, part := range splitCommands(tail) {
					p.parse(part, depth+1, "cmd "+arg, false)
				}
				return
			}
		}
		p.warn("cmd 命令未包含可解析的 /c 或 /k 参数")
	case "powershell", "pwsh":
		for i := 1; i < len(ts); i++ {
			arg := strings.ToLower(ts[i].value)
			if arg == "-file" || arg == "-f" {
				if i+1 < len(ts) {
					p.target(ts[i+1].value, name+" -File", false)
				}
				return
			}
			if arg == "-encodedcommand" || arg == "-enc" || arg == "-e" {
				p.chain.Encoded = true
				if i+1 >= len(ts) {
					p.warn("编码命令缺少数据")
					return
				}
				data, err := base64.StdEncoding.DecodeString(ts[i+1].value)
				if err != nil || len(data)%2 != 0 {
					p.warn("编码命令不是有效 UTF-16LE Base64")
					return
				}
				u := make([]uint16, len(data)/2)
				for j := range u {
					u[j] = binary.LittleEndian.Uint16(data[j*2:])
				}
				p.script(string(utf16.Decode(u)), depth+1, name+" -EncodedCommand")
				return
			}
			if arg == "-command" || arg == "-c" {
				tail := strings.TrimSpace(command[ts[i].end:])
				if i+2 == len(ts) && ts[i+1].quoted {
					tail = ts[i+1].value
				}
				p.script(tail, depth+1, name+" -Command")
				return
			}
		}
		p.warn("PowerShell 参数未能静态解析")
	case "rundll32":
		if len(ts) > 1 {
			value := strings.SplitN(ts[1].value, ",", 2)[0]
			p.target(value, name, false)
		}
	case "wscript", "cscript", "mshta", "regsvr32":
		for _, t := range ts[1:] {
			if strings.HasPrefix(strings.ToLower(t.value), "/i:") {
				p.target(t.value[3:], name, false)
			} else if !strings.HasPrefix(t.value, "/") && !strings.HasPrefix(t.value, "-") {
				p.target(t.value, name, false)
				break
			}
		}
	case "schtasks", "forfiles":
		flag := "/tr"
		if name == "forfiles" {
			flag = "/c"
		}
		for i := 1; i+1 < len(ts); i++ {
			if strings.EqualFold(ts[i].value, flag) {
				p.parse(ts[i+1].value, depth+1, name+" "+flag, false)
				return
			}
		}
		p.warn(name + " 未提供可静态展开的子命令")
	case "wmic":
		for i := 1; i+1 < len(ts); i++ {
			if strings.EqualFold(ts[i].value, "create") {
				p.parse(ts[i+1].value, depth+1, "wmic process create", false)
				return
			}
		}
	default:
		// Ordinary program arguments are evidence hints, not proof of execution.
		for _, t := range ts[1:] {
			if isFile(t.value) {
				p.target(t.value, "命令参数中的文件引用（需复核用途）", false)
			}
		}
	}
}

func (p *parser) script(script string, depth int, via string) {
	p.warn("PowerShell 仅静态提取命令和字面量；动态拼接、函数及条件分支未求值")
	for _, part := range splitCommands(script) {
		part = strings.TrimSpace(part)
		part = strings.TrimSpace(strings.TrimPrefix(part, "&"))
		p.parse(part, depth, via, false)
	}
	for _, value := range embeddedTarget.FindAllString(script, 32) {
		p.target(value, via+" 字面量引用（需复核用途）", false)
	}
}

func base(value string) string {
	value = strings.ReplaceAll(value, `\`, "/")
	value = value[strings.LastIndex(value, "/")+1:]
	return strings.TrimSuffix(strings.ToLower(value), ".exe")
}
func IsInterpreter(value string) bool {
	switch base(value) {
	case "cmd", "powershell", "pwsh", "rundll32", "regsvr32", "mshta", "wscript", "cscript", "wmic", "forfiles", "schtasks":
		return true
	}
	return false
}
func isFile(value string) bool {
	switch strings.ToLower(filepath.Ext(value)) {
	case ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".sys", ".com":
		return true
	}
	return false
}
