package policy

import (
	"crypto/ed25519"
	"testing"
)

func testPolicy() Policy {
	return Policy{
		ID:      "pol-1",
		Name:    "webroot",
		Version: 1,
		Paths: []PathRule{
			{Path: "/var/www/site", Recursive: true, Mode: ModeEnforce},
			{Path: "/var/www/site/cache", Recursive: true, Mode: ModeObserve},
			{Path: "/etc/nginx/nginx.conf", Recursive: false, Mode: ModeEnforce},
		},
		Writers: []WriterRule{{Kind: WriterPublisher, ID: "publisher-1"}},
	}
}

func liveGrant(now int64) Grant {
	return Grant{
		TokenID:   "tok-1",
		Subject:   "publisher-1",
		NodeID:    "node-1",
		Paths:     []string{"/var/www/site"},
		ExpiresAt: now + 300,
	}
}

func TestMatchPathMostSpecificWins(t *testing.T) {
	p := testPolicy()
	r, ok := p.MatchPath("/var/www/site/cache/a.html")
	if !ok || r.Mode != ModeObserve {
		t.Fatalf("expected observe rule for cache, got %+v ok=%v", r, ok)
	}
	r, ok = p.MatchPath("/var/www/site/index.html")
	if !ok || r.Mode != ModeEnforce {
		t.Fatalf("expected enforce rule, got %+v ok=%v", r, ok)
	}
	if _, ok := p.MatchPath("/var/www/other.html"); ok {
		t.Fatal("unprotected path matched")
	}
	if _, ok := p.MatchPath("/etc/nginx/nginx.conf.bak"); ok {
		t.Fatal("non-recursive rule must not match siblings")
	}
	if _, ok := p.MatchPath("/etc/nginx/nginx.conf"); !ok {
		t.Fatal("exact file rule did not match")
	}
}

func TestDecideMatrix(t *testing.T) {
	p := testPolicy()
	now := int64(1000)
	pub := Subject{Kind: WriterPublisher, ID: "publisher-1", PID: 42}

	cases := []struct {
		name  string
		req   Request
		allow bool
		why   string
	}{
		{
			name:  "unprotected path is free",
			req:   Request{Path: "/tmp/x", Subject: Subject{Kind: WriterProcess, ExePath: "/bin/sh"}, Now: now},
			allow: true,
			why:   ReasonNotProtected,
		},
		{
			name:  "observe rule allows but records",
			req:   Request{Path: "/var/www/site/cache/x", Subject: Subject{Kind: WriterProcess, ExePath: "/bin/sh"}, Now: now},
			allow: true,
			why:   ReasonObserve,
		},
		{
			name:  "webshell denied",
			req:   Request{Path: "/var/www/site/shell.php", Subject: Subject{Kind: WriterProcess, ExePath: "/bin/bash"}, Now: now},
			allow: false,
			why:   ReasonDenied,
		},
		{
			name:  "publisher without grant denied",
			req:   Request{Path: "/var/www/site/index.html", Subject: pub, Now: now},
			allow: false,
			why:   ReasonDenied,
		},
		{
			name:  "publisher with live grant allowed",
			req:   Request{Path: "/var/www/site/index.html", Subject: pub, Grants: []Grant{liveGrant(now)}, Now: now},
			allow: true,
			why:   ReasonGranted,
		},
		{
			name: "expired grant denied",
			req:  Request{Path: "/var/www/site/index.html", Subject: pub, Grants: []Grant{liveGrant(now - 1000)}, Now: now},
		},
		{
			name: "grant for another node denied",
			req: func() Request {
				g := liveGrant(now)
				g.NodeID = "other-node"
				return Request{NodeID: "node-1", Path: "/var/www/site/index.html", Subject: pub, Grants: []Grant{g}, Now: now}
			}(),
		},
		{
			name: "grant for another subject denied",
			req: func() Request {
				g := liveGrant(now)
				g.Subject = "publisher-2"
				return Request{NodeID: "node-1", Path: "/var/www/site/index.html", Subject: pub, Grants: []Grant{g}, Now: now}
			}(),
		},
		{
			name: "grant does not cover sibling tree",
			req: func() Request {
				g := liveGrant(now)
				g.Paths = []string{"/var/www/site-static"}
				return Request{NodeID: "node-1", Path: "/var/www/site/index.html", Subject: pub, Grants: []Grant{g}, Now: now}
			}(),
		},
		{
			name:  "relative path rejected",
			req:   Request{Path: "var/www/site/x", Subject: pub, Now: now},
			allow: false,
			why:   ReasonInvalidPath,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := p.Decide(tc.req)
			if d.Allow != tc.allow {
				t.Fatalf("allow=%v want %v (decision %+v)", d.Allow, tc.allow, d)
			}
			if tc.why != "" && d.Reason != tc.why {
				t.Fatalf("reason=%q want %q", d.Reason, tc.why)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	good := testPolicy()
	if err := good.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	bad := testPolicy()
	bad.Paths = append(bad.Paths, PathRule{Path: "relative/path", Mode: ModeEnforce})
	if err := bad.Validate(); err == nil {
		t.Fatal("relative path accepted")
	}

	noWriters := testPolicy()
	noWriters.Writers = []WriterRule{{Kind: WriterPublisher}}
	if err := noWriters.Validate(); err == nil {
		t.Fatal("publisher without id accepted")
	}

	emptyMode := testPolicy()
	emptyMode.Paths[0].Mode = ""
	if err := emptyMode.Validate(); err != nil {
		t.Fatalf("empty mode should default to enforce: %v", err)
	}
	if emptyMode.Paths[0].Mode != ModeEnforce {
		t.Fatal("empty mode not defaulted")
	}
}

func TestDigestIsOrderIndependent(t *testing.T) {
	a := testPolicy()
	b := testPolicy()
	b.Paths[0], b.Paths[2] = b.Paths[2], b.Paths[0]
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("digest depends on slice order: %s != %s", da, db)
	}
}

func TestSnapshotSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, err := SignSnapshot(testPolicy(), 123, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	s.Policy.Paths[0].Mode = ModeObserve
	if err := s.Verify(pub); err == nil {
		t.Fatal("modified snapshot accepted")
	}
}
