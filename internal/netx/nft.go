package netx

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Nft applies an nftables batch after a dry run, so a bad batch changes nothing.
func Nft(batch string) error {
	if err := nft(batch, "-c", "-f", "-"); err != nil {
		return err
	}
	return nft(batch, "-f", "-")
}

// DeleteTable removes a table if it exists.
func DeleteTable(name string) {
	_ = nft("", "delete", "table", "ip", name)
}

// NftList returns a table in JSON, or "" if it does not exist.
func NftList(name string) string {
	var out bytes.Buffer
	cmd := exec.Command("nft", "-j", "list", "table", "ip", name)
	cmd.Stdout = &out
	if cmd.Run() != nil {
		return ""
	}
	return out.String()
}

// NftTables lists ip-family table names.
func NftTables() []string {
	out, err := exec.Command("nft", "list", "tables", "ip").Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "table" && f[1] == "ip" {
			names = append(names, f[2])
		}
	}
	return names
}

// TableExists reports whether an ip-family table is present.
func TableExists(name string) bool {
	for _, t := range NftTables() {
		if t == name {
			return true
		}
	}
	return false
}

func nft(batch string, args ...string) error {
	cmd := exec.Command("nft", args...)
	cmd.Stdin = strings.NewReader(batch)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return fmt.Errorf("nft: %s", msg)
	}
	return nil
}
