//go:build windows

package process

import "testing"

func TestNormalizeExplorerTarget(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "path with spaces",
			input: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
			want:  `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		},
		{
			name:  "quoted path",
			input: `  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"  `,
			want:  `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		},
		{
			name:    "empty path",
			input:   "  ",
			wantErr: true,
		},
		{
			name:    "relative path",
			input:   `Application\chrome.exe`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeExplorerTarget(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeExplorerTarget(%q) expected error, got %q", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeExplorerTarget(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeExplorerTarget(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExplorerSelectParameters(t *testing.T) {
	path := `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
	want := `/select,"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"`
	if got := explorerSelectParameters(path); got != want {
		t.Fatalf("explorerSelectParameters() = %q, want %q", got, want)
	}
}
