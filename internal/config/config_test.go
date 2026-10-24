package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultRouteTakesTheLowestMetric(t *testing.T) {
	table := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
br-lan	0001A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
wan	00000000	0100A8C0	0003	0	0	20	00000000	0	0	0
pppoe-wan	00000000	01005EC0	0003	0	0	0	00000000	0	0	0
wwan	00000000	01005EC0	0002	0	0	0	00000000	0	0	0
`
	got, err := defaultRoute(strings.NewReader(table))
	if err != nil || got != "pppoe-wan" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := defaultRoute(strings.NewReader("Iface\tDestination\n")); err == nil {
		t.Fatal("no default route accepted")
	}
}

// A fresh install has no file: it must start, then ask for devices in the dashboard.
func TestStartsWithoutDevices(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Clients == nil || len(c.Clients) != 0 || c.Listen != "" || c.WAN != "" {
		t.Fatalf("defaults %+v", c)
	}
}

// Found values are used at run time but never written back.
func TestAutomaticFieldsStayEmptyOnSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "brutter.json")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Listen, c.autoListen = "192.168.1.1", true
	c.WAN, c.autoWAN = "wan", true
	c.Clients = []string{"192.168.1.100"}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if _, ok := saved["listen"]; ok {
		t.Fatalf("listen saved: %s", data)
	}
	if _, ok := saved["wan_interface"]; ok {
		t.Fatalf("WAN saved: %s", data)
	}
	if again, err := Load(path); err != nil || len(again.Clients) != 1 {
		t.Fatalf("reload %+v, %v", again, err)
	}
}
