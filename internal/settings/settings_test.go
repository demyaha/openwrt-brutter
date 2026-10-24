package settings

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// The dashboard reads games.length; null broke every render and locked the
// game picker, so no game could be turned back on.
func TestNoGamesStayAnEmptyList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	s := Open(path)
	if _, err := s.Update([]byte(`{"games":[]}`)); err != nil {
		t.Fatal(err)
	}
	for name, store := range map[string]*Store{"live": s, "reloaded": Open(path)} {
		data, _ := json.Marshal(store.Get())
		if !strings.Contains(string(data), `"games":[]`) {
			t.Fatalf("%s settings %s", name, data)
		}
	}
	if _, err := s.Update([]byte(`{"force":true}`)); err != nil {
		t.Fatal(err)
	}
	if data, _ := json.Marshal(s.Get()); !strings.Contains(string(data), `"games":[]`) {
		t.Fatalf("after an unrelated change %s", data)
	}
}
