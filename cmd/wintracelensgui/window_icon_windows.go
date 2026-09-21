//go:build windows

//go:generate go run github.com/akavel/rsrc@v0.10.2 -arch amd64 -ico assets/wintracelens.ico -o rsrc_windows_amd64.syso

package main

// rsrc assigns ID 1 to the first icon group when no manifest is embedded.
const appIconResourceID = 1
