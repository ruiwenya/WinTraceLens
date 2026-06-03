package runtimeinfo

import "runtime"

type Info struct {
	Version       string `json:"version"`
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	IsAdmin       bool   `json:"isAdmin"`
	AdminKnown    bool   `json:"adminKnown"`
	Compatibility string `json:"compatibility"`
}

func Collect(version string) Info {
	isAdmin, adminKnown := adminStatus()
	return Info{
		Version:       version,
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		IsAdmin:       isAdmin,
		AdminKnown:    adminKnown,
		Compatibility: compatibilitySummary(),
	}
}
