package aianalysis

import (
	"strings"
	"testing"
)

func TestRedactSensitiveText(t *testing.T) {
	input := `host=10.23.4.5 path=C:\Users\Alice\AppData account=CORP\alice share=\\fileserver\case public=8.8.8.8`
	got := redactSensitiveText(input)
	for _, secret := range []string{"10.23.4.5", `C:\Users\Alice`, `CORP\alice`, `\\fileserver\`} {
		if strings.Contains(got, secret) {
			t.Fatalf("sensitive value %q was not redacted: %s", secret, got)
		}
	}
	if !strings.Contains(got, "8.8.8.8") {
		t.Fatalf("public IP should remain visible: %s", got)
	}
}
