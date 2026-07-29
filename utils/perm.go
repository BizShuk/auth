package utils

import "os"

// 憑證檔含長期 secret,目錄與檔案權限一律鎖到 owner-only。
//
// 常數放在 stdlib-only 的 utils,讓每個建立憑證 store 的組裝點 (auth 的
// CLI、proxy 的伺服器) 共用同一組值,而不是各自寫死字面值。
const (
	AUTH_DIR_PERM  os.FileMode = 0o700
	AUTH_FILE_PERM os.FileMode = 0o600
)
