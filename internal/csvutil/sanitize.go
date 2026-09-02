package csvutil

import "strings"

// SanitizeRow neutralizes spreadsheet formulas without modifying JSON evidence.
func SanitizeRow(row []string) []string {
	out := make([]string, len(row))
	for i, value := range row {
		value = strings.Join(strings.Fields(strings.ReplaceAll(value, "\x00", "")), " ")
		if value != "" && strings.ContainsRune("=+-@", rune(value[0])) {
			value = "'" + value
		}
		out[i] = value
	}
	return out
}
