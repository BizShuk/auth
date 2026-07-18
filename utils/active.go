package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ACTIVE_FILE_NAME is the per-directory JSON file mapping provider family to
// the active credential name. The auth CLI "use" command writes it; Resolver
// consults it before falling back to alphabetic selection.
const ACTIVE_FILE_NAME = "active.json"

// LoadActiveNames reads the provider→credential-name selection map from dir.
// A missing file is an empty selection, not an error.
func LoadActiveNames(dir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ACTIVE_FILE_NAME))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read active credential selection: %w", err)
	}
	active := make(map[string]string)
	if err := json.Unmarshal(raw, &active); err != nil {
		return nil, fmt.Errorf("parse active credential selection: %w", err)
	}
	return active, nil
}

// SaveActiveName records name as the active credential for provider, using
// the same temp+rename and 0600 discipline as credential files.
func SaveActiveName(dir, provider, name string) error {
	active, err := LoadActiveNames(dir)
	if err != nil {
		return err
	}
	active[provider] = name

	payload, err := json.MarshalIndent(active, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize active credential selection: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-active-*.json")
	if err != nil {
		return fmt.Errorf("create temp active file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(AUTH_FILE_PERM); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod active file: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write active file: %w", err)
	}
	_ = tmp.Close()

	if err := os.Rename(tmpName, filepath.Join(dir, ACTIVE_FILE_NAME)); err != nil {
		return fmt.Errorf("commit active file: %w", err)
	}
	return nil
}
