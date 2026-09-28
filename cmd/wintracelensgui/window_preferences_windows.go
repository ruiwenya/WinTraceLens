//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const (
	windowFrameIntegrated = "integrated"
	windowFrameSystem     = "system"
)

type persistedUIPreferences struct {
	WindowFrame string `json:"windowFrame"`
}

func windowPreferencesPath() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "WinTraceLens", "ui-preferences.json")
}

func loadWindowFramePreference(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return windowFrameIntegrated, nil
	}
	if err != nil {
		return windowFrameIntegrated, err
	}
	var preferences persistedUIPreferences
	if err := json.Unmarshal(data, &preferences); err != nil {
		return windowFrameIntegrated, err
	}
	if preferences.WindowFrame != windowFrameIntegrated && preferences.WindowFrame != windowFrameSystem {
		return windowFrameIntegrated, errors.New("invalid saved window frame preference")
	}
	return preferences.WindowFrame, nil
}

func saveWindowFramePreference(path, preference string) error {
	if preference != windowFrameIntegrated && preference != windowFrameSystem {
		return errors.New("invalid window frame preference")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(persistedUIPreferences{WindowFrame: preference}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}
