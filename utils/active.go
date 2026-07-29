package utils

import "os"

// 憑證檔含長期 secret,目錄與檔案權限一律鎖到 owner-only。
const (
	AUTH_DIR_PERM  os.FileMode = 0o700
	AUTH_FILE_PERM os.FileMode = 0o600
)

// ACTIVE_NAME is the stem of the legacy per-directory selection file.
//
// Selection now lives in the application's settings file (see auth/active),
// so nothing writes this any more. The name is kept because installs made
// before the move still have active.json sitting in their credential
// directory, and a credential listing must not report it as a credential —
// it decodes into an empty Credential without error, since json.Unmarshal
// ignores unknown fields.
const ACTIVE_NAME = "active"
