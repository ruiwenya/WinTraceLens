package aianalysis

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	ipv4Pattern     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	userPathPattern = regexp.MustCompile(`(?i)([a-z]:\\{1,2}users\\{1,2})([^\\/"\s]+)`)
	uncHostPattern  = regexp.MustCompile(`(\\{2,4})([A-Za-z0-9][A-Za-z0-9._-]{1,62})(\\{1,2})`)
	accountPattern  = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9._-]{1,62})\\{1,2}([A-Za-z0-9.$_-]{1,63})\b`)
)

func redactSensitiveText(value string) string {
	replacements := make(map[string]string)
	counter := make(map[string]int)
	placeholder := func(kind, source string) string {
		key := kind + "\x00" + strings.ToLower(source)
		if existing := replacements[key]; existing != "" {
			return existing
		}
		counter[kind]++
		result := fmt.Sprintf("<%s_%d>", kind, counter[kind])
		replacements[key] = result
		return result
	}

	value = ipv4Pattern.ReplaceAllStringFunc(value, func(candidate string) string {
		ip := net.ParseIP(candidate)
		if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) {
			return candidate
		}
		return placeholder("PRIVATE_IP", candidate)
	})
	value = userPathPattern.ReplaceAllStringFunc(value, func(candidate string) string {
		parts := userPathPattern.FindStringSubmatch(candidate)
		if len(parts) != 3 {
			return candidate
		}
		return parts[1] + placeholder("USER", parts[2])
	})
	value = uncHostPattern.ReplaceAllStringFunc(value, func(candidate string) string {
		parts := uncHostPattern.FindStringSubmatch(candidate)
		if len(parts) != 4 {
			return candidate
		}
		return parts[1] + placeholder("HOST", parts[2]) + parts[3]
	})
	value = accountPattern.ReplaceAllStringFunc(value, func(candidate string) string {
		parts := accountPattern.FindStringSubmatch(candidate)
		if len(parts) != 3 || looksLikeWindowsPath(parts[1]) {
			return candidate
		}
		return placeholder("DOMAIN", parts[1]) + `\\` + placeholder("ACCOUNT", parts[2])
	})
	return value
}

func looksLikeWindowsPath(value string) bool {
	switch strings.ToLower(value) {
	case "windows", "systemroot", "system32", "program files", "programdata", "users", "device", "registry":
		return true
	default:
		return false
	}
}
