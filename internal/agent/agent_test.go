package agent

import (
	"reflect"
	"testing"

	"github.com/easykeke/tamperguard/internal/policy"
)

func TestEffectivePublisherUIDs(t *testing.T) {
	uidA, uidB := 1002, 1003
	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "p", Name: "p", Version: 1,
		Writers: []policy.WriterRule{
			{Kind: policy.WriterPublisher, ID: "pub_1"},
			{Kind: policy.WriterProcess, ExePath: "/usr/bin/rsync", UID: &uidA},
			{Kind: policy.WriterProcess, ExePath: "/usr/bin/rsync", UID: &uidA}, // duplicate
			{Kind: policy.WriterProcess, ExePath: "/usr/bin/find"},              // no uid
			{Kind: policy.WriterProcess, ExePath: "/opt/tool", UID: &uidB},
		},
	}}

	got := effectivePublisherUIDs([]int{0, uidA}, snap)
	want := []int{0, uidA, uidB}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	// No policy: configured uids only.
	if got := effectivePublisherUIDs([]int{7}, nil); !reflect.DeepEqual(got, []int{7}) {
		t.Fatalf("nil policy: got %v", got)
	}
	// No configured uids: policy uids only.
	if got := effectivePublisherUIDs(nil, snap); !reflect.DeepEqual(got, []int{uidA, uidB}) {
		t.Fatalf("no base: got %v", got)
	}
}
