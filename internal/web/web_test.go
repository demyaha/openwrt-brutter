package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The brand pill must not change width when the first status arrives.
func TestPageCarriesTheVersion(t *testing.T) {
	s := &Server{Version: "1.2.3"}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if body := rec.Body.String(); !strings.Contains(body, `<small id="version">v1.2.3</small>`) {
		t.Fatalf("version missing from the page (status %d)", rec.Code)
	}
}
