// Package coverage describes what a collection can and cannot establish.
package coverage

import "sort"

type Summary struct {
	Status            string   `json:"status"`
	Returned          int      `json:"returned"`
	Limit             int      `json:"limit"`
	LimitScope        string   `json:"limitScope"`
	LimitReached      bool     `json:"limitReached"`
	PossiblyTruncated bool     `json:"possiblyTruncated"`
	Sort              string   `json:"sort"`
	Earliest          string   `json:"earliest,omitempty"`
	Latest            string   `json:"latest,omitempty"`
	Roots             []string `json:"roots,omitempty"`
	Sources           []string `json:"sources,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
	Boundary          string   `json:"boundary"`
}

func Times(values []string) (string, string) {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	if len(filtered) == 0 {
		return "", ""
	}
	sort.Strings(filtered)
	return filtered[0], filtered[len(filtered)-1]
}

func Clone(value *Summary) *Summary {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Roots = append([]string(nil), value.Roots...)
	copy.Sources = append([]string(nil), value.Sources...)
	copy.Warnings = append([]string(nil), value.Warnings...)
	return &copy
}
