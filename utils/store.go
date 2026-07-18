package utils

import (
	"encoding/json"
	"fmt"
	"github.com/bizshuk/auth/model"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// 憑證檔含長期 secret,目錄與檔案權限一律鎖到 owner-only。
const (
	AUTH_DIR_PERM  os.FileMode = 0o700
	AUTH_FILE_PERM os.FileMode = 0o600
)

// FileStore 把 model.Credential 以每帳號一個 JSON 檔的方式存在磁碟上。
//
// 寫入是 atomic (temp + rename),避免中途中斷留下半截的憑證檔 — 與
// memory/filestore 的 StateStore 同一套做法。
type FileStore struct {
	dir string
}

// NewFileStore 建立 store 並確保目錄存在。
func NewFileStore(dir string) (*FileStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("auth: file store dir must not be empty")
	}
	if err := os.MkdirAll(dir, AUTH_DIR_PERM); err != nil {
		return nil, fmt.Errorf("auth: create auth dir %s: %w", dir, err)
	}
	return &FileStore{dir: dir}, nil
}

// Dir 回傳憑證目錄。
func (s *FileStore) Dir() string { return s.dir }

// Path 回傳某個憑證的檔案路徑。
func (s *FileStore) Path(name string) string {
	return filepath.Join(s.dir, name+".json")
}

// Save 持久化憑證,以 cred.Name() 為鍵。
func (s *FileStore) Save(cred *model.Credential) error {
	if err := cred.Validate(); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return fmt.Errorf("auth: marshal credential: %w", err)
	}

	path := s.Path(cred.Name())
	tmp, err := os.CreateTemp(s.dir, ".tmp-*.json")
	if err != nil {
		return fmt.Errorf("auth: create temp credential file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // rename 成功後這裡是 no-op

	if err := tmp.Chmod(AUTH_FILE_PERM); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auth: chmod temp credential file: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("auth: write credential: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("auth: close temp credential file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("auth: commit credential file: %w", err)
	}
	return nil
}

// Load 讀出一份憑證。找不到時回傳 model.ErrNotFound。
func (s *FileStore) Load(name string) (*model.Credential, error) {
	raw, err := os.ReadFile(s.Path(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", model.ErrNotFound, name)
		}
		return nil, fmt.Errorf("auth: read credential %s: %w", name, err)
	}
	var cred model.Credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, fmt.Errorf("auth: parse credential %s: %w", name, err)
	}
	return &cred, nil
}

// List 回傳目錄下所有憑證,依 Name() 排序。無法解析的檔案直接跳過,
// 不讓一個壞檔擋掉整個列表。
func (s *FileStore) List() ([]*model.Credential, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auth: list auth dir: %w", err)
	}

	var creds []*model.Credential
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		cred, err := s.Load(name)
		if err != nil {
			continue
		}
		creds = append(creds, cred)
	}
	sort.Slice(creds, func(i, j int) bool { return creds[i].Name() < creds[j].Name() })
	return creds, nil
}

// Delete 移除一份憑證。找不到時回傳 model.ErrNotFound。
func (s *FileStore) Delete(name string) error {
	if err := os.Remove(s.Path(name)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", model.ErrNotFound, name)
		}
		return fmt.Errorf("auth: delete credential %s: %w", name, err)
	}
	return nil
}
