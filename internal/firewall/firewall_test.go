package firewall

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fake struct {
	calls  []string
	reject bool
}

func (f *fake) run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.reject && args[0] == "check" {
		return []byte("Error: chain forward_lan does not exist"), errors.New("exit 1")
	}
	return nil, nil
}

var pc = []netip.Addr{netip.MustParseAddr("192.168.1.100"), netip.MustParseAddr("192.168.1.101")}

func TestRenderNamesEveryDeviceAndTheLAN(t *testing.T) {
	got := Render("br-lan", pc)
	for _, want := range []string{`ip saddr { 192.168.1.100, 192.168.1.101 }`, `iifname "br-lan"`, "jump forward_lan"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	if Render("br-lan", nil) != "" {
		t.Fatal("an empty selection needs no include")
	}
}

func TestSyncWritesReplacesAndReloadsOnlyOnChange(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, legacy[1]), []byte("old rule"), 0o644)
	f := &fake{}
	in := &Include{Dir: dir, FW4: f.run}
	if err := in.Sync("br-lan", pc); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, legacy[1])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("hand-made include left in place")
	}
	if strings.Join(f.calls, ",") != "check,reload" {
		t.Fatalf("calls %v", f.calls)
	}
	f.calls = nil
	if err := in.Sync("br-lan", pc); err != nil || len(f.calls) != 0 {
		t.Fatalf("unchanged include reloaded the firewall: %v %v", f.calls, err)
	}
	if err := in.Sync("br-lan", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("include kept without devices")
	}
}

// A ruleset firewall4 rejects must never reach a reload.
func TestSyncRollsBackARejectedRuleset(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, legacy[0]), []byte("old rule"), 0o644)
	f := &fake{reject: true}
	in := &Include{Dir: dir, FW4: f.run}
	if err := in.Sync("br-lan", pc); err == nil {
		t.Fatal("rejected ruleset reported as applied")
	}
	if strings.Join(f.calls, ",") != "check" {
		t.Fatalf("calls %v", f.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected include left in place")
	}
	if data, _ := os.ReadFile(filepath.Join(dir, legacy[0])); string(data) != "old rule" {
		t.Fatal("hand-made include not restored")
	}
}

func TestSyncSkipsSystemsWithoutFirewall4Includes(t *testing.T) {
	f := &fake{}
	in := &Include{Dir: filepath.Join(t.TempDir(), "missing"), FW4: f.run}
	if err := in.Sync("br-lan", pc); err != nil || len(f.calls) != 0 {
		t.Fatalf("%v %v", f.calls, err)
	}
}
