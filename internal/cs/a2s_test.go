package cs

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func info(name string) []byte {
	p := []byte("\xff\xff\xff\xffI\x11")
	p = append(p, name...)
	p = append(p, 0)
	p = append(p, "de_mirage\x00csgo\x00Counter-Strike 2\x00"...)
	p = append(p, 0xda, 0x02, 7, 10, 0, 'd', 'l', 0, 1)
	return append(p, "1.40.0.0\x00"...)
}

func TestParseInfoReadsTheServerName(t *testing.T) {
	got, err := ParseInfo(info("Mirage 24/7 \x01|\x02 128 tick"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Mirage 24/7 | 128 tick" || got.Map != "de_mirage" || got.AppID != 730 ||
		got.Players != 7 || got.MaxPlayers != 10 {
		t.Fatalf("%+v", got)
	}
	if _, err := ParseInfo(info("x")[:30]); err == nil {
		t.Fatal("truncated reply accepted")
	}
}

func TestNamesStayPrintableAndShort(t *testing.T) {
	cases := map[string]string{
		"Emoji 🔥 HvH 🇷🇺":                        "Emoji 🔥 HvH 🇷🇺",
		"<img src=x onerror=alert(1)>":          "<img src=x onerror=alert(1)>", // shown as text by the panel
		"abc\u202edcba":                         "abcdcba",
		"zero\u200bwidth\ufeff":                 "zerowidth",
		"  many   spaces\t\there ":              "many spaces here",
		"\x07colour\x04 codes":                  "colour codes",
		"\xcf\xf0\xe8\xe2\xe5\xf2 \xec\xe8\xf0": "Привет мир", // Windows-1251
	}
	for in, want := range cases {
		if got := clean([]byte(in)); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("a", 62) + "👍🏽x"
	if got := clean([]byte(long)); got != strings.Repeat("a", 62)+"👍…" {
		t.Errorf("skin tone cut: %q", got)
	}
	flag := strings.Repeat("b", 63) + "🇷🇺"
	if got := clean([]byte(flag)); got != strings.Repeat("b", 63)+"…" {
		t.Errorf("half a flag kept: %q", got)
	}
	if n := utf8.RuneCountInString(clean([]byte(strings.Repeat("я", 300)))); n != 65 {
		t.Errorf("long name kept %d runes", n)
	}
}
