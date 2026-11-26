// Package publish: local sync profile.
package publish

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Profile is the publisher's saved sync target, so the everyday command can be
// a single `tg-publish sync` with no arguments.
type Profile struct {
	NodeID    string `json:"node_id"`
	SourceDir string `json:"source_dir"`
	TargetDir string `json:"target_dir"`
	Mode      string `json:"mode"`
	Delivery  string `json:"delivery"`
}

// ProfilePath is where the profile lives inside the publisher state directory.
func ProfilePath(stateDir string) string { return filepath.Join(stateDir, "sync.json") }

// LoadProfile returns an empty profile when none has been saved yet.
func LoadProfile(stateDir string) (*Profile, error) {
	raw, err := os.ReadFile(ProfilePath(stateDir))
	if os.IsNotExist(err) {
		return &Profile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// SaveProfile persists the profile (0600).
func SaveProfile(stateDir string, p *Profile) error {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := ProfilePath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ProfilePath(stateDir))
}
