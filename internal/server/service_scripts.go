package server

import (
	"net/http"
	"strings"

	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
)

func (s *Server) handleServiceScripts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	service := strings.TrimSpace(r.URL.Query().Get("name"))
	if service == "" || len(service) > 128 {
		http.Error(w, "服务名不能为空", http.StatusBadRequest)
		return
	}
	snapshot, err := s.evidenceStore.NativeFiles(filetrace.Options{MaxRecords: 800, Hours: 24 * 30}, boolFromQuery(r, "refresh", false))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items := make([]filetrace.Record, 0)
	for _, item := range snapshot.Records {
		for _, related := range item.RelatedServices {
			if strings.EqualFold(strings.TrimSpace(related), service) {
				items = append(items, item)
				break
			}
		}
		if len(items) >= 50 {
			break
		}
	}
	writeJSON(w, struct {
		Items            []filetrace.Record `json:"items"`
		Count            int                `json:"count"`
		CollectionErrors []string           `json:"collectionErrors"`
	}{Items: items, Count: len(items), CollectionErrors: snapshot.CollectionErrors})
}
