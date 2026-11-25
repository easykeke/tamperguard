package token

import "testing"

func TestNormalizeWindowsPaths(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`C:\inetpub\wwwroot`, "C:/inetpub/wwwroot", true},
		{`c:\inetpub\wwwroot`, "C:/inetpub/wwwroot", true},
		{`C:/inetpub/wwwroot`, "C:/inetpub/wwwroot", true},
		{`C:\inetpub\..\Windows`, "", false},
		{`C:\`, "C:/", true},
		{`\\server\share\dir`, "//server/share/dir", true},
		{`\\server\share\..\x`, "", false},
		{`relative\path`, "", false},
		{`C:relative`, "", false},
		{"/var/www", "/var/www", true},
	}
	for _, tc := range cases {
		got, ok := NormalizePath(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("NormalizePath(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPathCoveredWindows(t *testing.T) {
	cases := []struct {
		base, target string
		want         bool
	}{
		{`C:\inetpub\wwwroot`, `C:\inetpub\wwwroot\a\b.html`, true},
		{`C:\inetpub\wwwroot`, `c:\INETPUB\WWWROOT\a.html`, true}, // case-insensitive
		{`C:\inetpub\wwwroot`, `C:\inetpub\wwwroot-evil\x.html`, false},
		{`C:\`, `C:\anything\x`, true},
		{`\\server\share`, `\\server\share\dir\f`, true},
	}
	for _, tc := range cases {
		if got := PathCovered(tc.base, tc.target); got != tc.want {
			t.Errorf("PathCovered(%q,%q) = %v want %v", tc.base, tc.target, got, tc.want)
		}
	}
}
