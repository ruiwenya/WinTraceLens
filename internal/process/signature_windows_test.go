//go:build windows

package process

import "testing"

func TestWinTrustCacheOnlyFlag(t *testing.T) {
	if wtdCacheOnlyURLRetrieval != 0x00001000 {
		t.Fatalf("WTD_CACHE_ONLY_URL_RETRIEVAL = %#x", wtdCacheOnlyURLRetrieval)
	}
}
