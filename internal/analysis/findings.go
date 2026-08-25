package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/registryanomaly"
	"github.com/ruiwenya/WinTraceLens/internal/selfidentity"
)

const (
	levelHigh   = "高"
	levelMedium = "中"
	levelLow    = "低"

	signatureUnsigned = "无签名请注意!!!"
	signatureBad      = "签名异常"
	signatureSystem   = "系统文件"
)

type Finding struct {
	Level        string `json:"level"`
	Source       string `json:"source"`
	Name         string `json:"name"`
	Reason       string `json:"reason"`
	MD5          string `json:"md5"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	Path         string `json:"path"`
	Command      string `json:"command"`
	Extra        string `json:"extra"`
}

// RegistryFindings promotes only medium/high registry anomalies into the shared
// risk list. Low-level records remain available in the dedicated registry view.
func RegistryFindings(snapshot registryanomaly.Snapshot) []Finding {
	findings := make([]Finding, 0, len(snapshot.Records))
	for _, item := range snapshot.Records {
		if item.Level != levelHigh && item.Level != levelMedium {
			continue
		}
		path := strings.Trim(strings.TrimSpace(item.Hive+`\`+item.KeyPath), `\`)
		name := path + `\` + item.ValueName
		findings = append(findings, Finding{
			Level:   item.Level,
			Source:  "注册表异常",
			Name:    name,
			Reason:  strings.Join(item.Reasons, "；"),
			Path:    path,
			Command: item.StringsPreview,
			Extra: fmt.Sprintf("类型=%s；长度=%d；熵=%.2f；SHA256=%s；关联=%s",
				item.ValueType, item.DataLength, item.Entropy, item.SHA256, strings.Join(item.Associations, "；")),
		})
	}
	return findings
}

func BuildFindings(processes []process.Info, snapshot host.Snapshot) []Finding {
	var findings []Finding

	for _, item := range processes {
		if selfidentity.IsSelfProcess(item.PID, item.Path) {
			continue
		}
		name := fmt.Sprintf("%s (PID %d)", item.Name, item.PID)
		command := item.Path
		extra := fmt.Sprintf("父进程: %s (%d), 连接数: %d", item.ParentName, item.ParentPID, item.ConnectionCount)
		if !isExpectedPowerShellCollectorAccessNoise(item) {
			findings = append(findings, executableFindings("进程", name, item.MD5, item.Signature, item.SignatureMsg, item.Path, command, item.HashError, item.PathError, extra, item.ConnectionCount)...)
		}
		if item.EnumerationWarning != "" && !isExpectedPowerShellEnumerationNoise(item) {
			level := levelLow
			if item.Path != "" || item.ConnectionCount > 0 {
				level = levelMedium
			}
			findings = append(findings, Finding{
				Level:  level,
				Source: "进程枚举差异",
				Name:   name,
				Reason: item.EnumerationWarning,
				Path:   item.Path,
				Extra:  item.EnumerationSources,
			})
		}
	}

	for _, item := range snapshot.Services {
		extra := fmt.Sprintf("状态: %s, 启动: %s, 账户: %s", item.State, item.StartMode, item.Account)
		findings = append(findings, executableFindings("服务", displayName(item.Name, item.DisplayName), item.MD5, item.Signature, item.SignatureMsg, item.Path, item.Command, item.HashError, "", extra, 0)...)
		if item.RiskLevel != "" {
			findings = append(findings, Finding{
				Level: item.RiskLevel, Source: "服务多源核查", Name: displayName(item.Name, item.DisplayName),
				Reason: strings.Join(item.RiskReasons, "；"), MD5: item.MD5, Signature: item.Signature,
				SignatureMsg: item.SignatureMsg, Path: item.Path, Command: item.Command,
				Extra: fmt.Sprintf("来源=%s；SCM=%s；注册表=%s；WMI=%s；ServiceDLL=%s", item.SourceStatus, item.SCMPath, item.RegistryImagePath, item.WMIPath, item.ServiceDLL),
			})
		}
	}

	for _, item := range snapshot.ScheduledTasks {
		if item.Executable == "" && item.MD5 == "" && item.HashError == "" && item.Signature == "" {
			continue
		}
		extra := fmt.Sprintf("任务路径: %s, 状态: %s/%s, 作者: %s", item.Path, item.State, item.Status, item.Author)
		command := strings.TrimSpace(item.Command + " " + item.Arguments)
		findings = append(findings, executableFindings("计划任务", item.Name, item.MD5, item.Signature, item.SignatureMsg, item.Executable, command, item.HashError, "", extra, 0)...)
	}

	for _, item := range snapshot.StartupItems {
		extra := fmt.Sprintf("来源: %s, 位置: %s", item.Source, item.Location)
		findings = append(findings, executableFindings("启动项", item.Name, item.MD5, item.Signature, item.SignatureMsg, item.Path, item.Command, item.HashError, "", extra, 0)...)
	}

	for _, item := range snapshot.ImageHijacks {
		reason := "存在 Image File Execution Options Debugger 项"
		if item.Signature == signatureBad || item.Signature == signatureUnsigned {
			reason += "，且 Debugger " + item.Signature
		}
		findings = append(findings, Finding{
			Level:        levelHigh,
			Source:       "镜像劫持",
			Name:         item.Image,
			Reason:       reason,
			MD5:          item.MD5,
			Signature:    item.Signature,
			SignatureMsg: item.SignatureMsg,
			Path:         item.Path,
			Command:      item.Debugger,
			Extra:        item.RegistryPath,
		})
	}

	for _, item := range snapshot.WMISubscriptions {
		if item.RiskLevel != levelHigh && item.RiskLevel != levelMedium {
			continue
		}
		name := strings.TrimSpace(item.FilterName + " -> " + item.ConsumerName)
		if name == "->" || name == "" {
			name = firstFindingValue(item.FilterPath, item.ConsumerPath, item.BindingPath)
		}
		command := strings.TrimSpace(firstFindingValue(item.CommandLine, item.ExecutablePath, item.ScriptText))
		findings = append(findings, Finding{
			Level:        item.RiskLevel,
			Source:       "WMI 永久事件订阅",
			Name:         name,
			Reason:       strings.Join(item.RiskReasons, "；"),
			MD5:          item.ExecutableMD5,
			Signature:    item.ExecutableSignature,
			SignatureMsg: item.ExecutableSigMsg,
			Path:         item.ExecutablePath,
			Command:      command,
			Extra: fmt.Sprintf("评分=%d；状态=%s；命名空间=%s；类型=%s；查询=%s；服务关联=%s；任务关联=%s",
				item.RiskScore, item.Status, item.Namespace, item.ConsumerType, item.Query,
				strings.Join(item.RelatedServices, ","), strings.Join(item.RelatedTasks, ",")),
		})
	}

	for _, item := range snapshot.Users {
		if item.LocalAccount && !item.Disabled && !item.PasswordRequired {
			findings = append(findings, Finding{
				Level:  levelMedium,
				Source: "用户",
				Name:   item.Name,
				Reason: "启用的本地账户未要求密码",
				Extra:  item.SID,
			})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank(findings[i].Level) != severityRank(findings[j].Level) {
			return severityRank(findings[i].Level) > severityRank(findings[j].Level)
		}
		if findings[i].Source != findings[j].Source {
			return findings[i].Source < findings[j].Source
		}
		return findings[i].Name < findings[j].Name
	})
	return findings
}

func firstFindingValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isExpectedPowerShellEnumerationNoise(item process.Info) bool {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item.Name)), ".exe")
	if name != "powershell" && name != "pwsh" {
		return false
	}
	if item.ConnectionCount != 0 {
		return false
	}

	collectorChild := selfidentity.IsScannerProcessName(item.ParentName)
	if !collectorChild && item.Signature != signatureSystem && item.Signature != "已签名" {
		return false
	}
	path := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(item.Path), "/", `\`))
	return collectorChild || strings.Contains(path, `\windows\system32\windowspowershell\`) ||
		strings.Contains(path, `\program files\powershell\`)
}

func isExpectedPowerShellCollectorAccessNoise(item process.Info) bool {
	if item.ConnectionCount != 0 || item.Path != "" || (item.HashError == "" && item.PathError == "") {
		return false
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item.Name)), ".exe")
	parent := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item.ParentName)), ".exe")
	if (name == "powershell" || name == "pwsh") && selfidentity.IsScannerProcessName(parent) {
		return true
	}
	return name == "conhost" && (parent == "powershell" || parent == "pwsh")
}

func executableFindings(source, name, md5, signature, signatureMsg, path, command, hashError, pathError, extra string, connectionCount int) []Finding {
	var findings []Finding
	if source == "进程" && selfidentity.IsSelfExecutablePath(path) {
		return findings
	}
	if signature == signatureSystem {
		return findings
	}

	if signature == signatureBad {
		findings = append(findings, Finding{
			Level:        levelHigh,
			Source:       source,
			Name:         name,
			Reason:       "签名异常",
			MD5:          md5,
			Signature:    signature,
			SignatureMsg: signatureMsg,
			Path:         path,
			Command:      command,
			Extra:        extra,
		})
	}

	if signature == signatureUnsigned {
		level := levelMedium
		reason := "无签名可执行文件"
		if connectionCount > 0 {
			level = levelHigh
			reason = fmt.Sprintf("无签名且存在网络连接 (%d)", connectionCount)
		} else if isWritableLocation(path) {
			level = levelHigh
			reason = "无签名且位于用户可写路径"
		}
		findings = append(findings, Finding{
			Level:        level,
			Source:       source,
			Name:         name,
			Reason:       reason,
			MD5:          md5,
			Signature:    signature,
			SignatureMsg: signatureMsg,
			Path:         path,
			Command:      command,
			Extra:        extra,
		})
	}

	if hashError != "" || pathError != "" {
		reason := strings.TrimSpace(strings.Join([]string{hashError, pathError}, " "))
		findings = append(findings, Finding{
			Level:     levelMedium,
			Source:    source,
			Name:      name,
			Reason:    "文件访问或 MD5 计算失败",
			Signature: signature,
			Path:      path,
			Command:   command,
			Extra:     strings.TrimSpace(extra + " " + reason),
		})
	}

	if path != "" && isWritableLocation(path) && signature != signatureUnsigned && signature != signatureBad {
		findings = append(findings, Finding{
			Level:        levelLow,
			Source:       source,
			Name:         name,
			Reason:       "可执行文件位于用户可写路径",
			MD5:          md5,
			Signature:    signature,
			SignatureMsg: signatureMsg,
			Path:         path,
			Command:      command,
			Extra:        extra,
		})
	}

	return findings
}

func isWritableLocation(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	for _, marker := range []string{
		`\users\`,
		`\appdata\`,
		`\temp\`,
		`\tmp\`,
		`\downloads\`,
		`\desktop\`,
		`\public\`,
		`\programdata\`,
		`\recycler\`,
		`\$recycle.bin\`,
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func displayName(name, display string) string {
	if display == "" || display == name {
		return name
	}
	return name + " / " + display
}

func severityRank(level string) int {
	switch level {
	case levelHigh:
		return 3
	case levelMedium:
		return 2
	case levelLow:
		return 1
	default:
		return 0
	}
}
