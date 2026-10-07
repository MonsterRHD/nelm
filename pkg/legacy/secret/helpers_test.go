package secret

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	cgsecret "github.com/werf/common-go/pkg/secret"
)

func rtTestSecretKey(t *testing.T) []byte {
	t.Helper()

	key, err := cgsecret.GenerateAesSecretKey()
	require.NoError(t, err)

	return key
}

func rtTestEncoder(t *testing.T, key []byte) *cgsecret.YamlEncoder {
	t.Helper()

	aesEncoder, err := cgsecret.NewAesEncoder(key)
	require.NoError(t, err)

	return cgsecret.NewYamlEncoder(aesEncoder)
}

func rtEncrypt(t *testing.T, encoder *cgsecret.YamlEncoder, plainData []byte, values bool) []byte {
	t.Helper()

	if values {
		encrypted, err := encoder.EncryptYamlData(plainData)
		require.NoError(t, err)

		return encrypted
	}

	encrypted, err := encoder.Encrypt(plainData)
	require.NoError(t, err)

	return append(encrypted, '\n')
}

func rtDecrypt(t *testing.T, encoder *cgsecret.YamlEncoder, encryptedData []byte, values bool) []byte {
	t.Helper()

	trimmed := bytes.TrimSpace(encryptedData)

	if values {
		decrypted, err := encoder.DecryptYamlData(trimmed)
		require.NoError(t, err)

		return decrypted
	}

	decrypted, err := encoder.Decrypt(trimmed)
	require.NoError(t, err)

	return decrypted
}

func rtWriteFile(t *testing.T, filePath string, data []byte, mode os.FileMode) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0o755))
	require.NoError(t, os.WriteFile(filePath, data, mode))
}

func rtSetKeys(t *testing.T, oldKey, newKey []byte) {
	t.Helper()

	t.Setenv("WERF_OLD_SECRET_KEY", string(oldKey))
	t.Setenv("WERF_SECRET_KEY", string(newKey))
}

func rtRunRotate(t *testing.T, chartDir, secretWorkDir string, secretValuesPaths ...string) {
	t.Helper()

	require.NoError(t, RotateSecretKey(context.Background(), chartDir, secretWorkDir, secretValuesPaths...))
}

func rtAssertNoSentinels(t *testing.T, rootDirs ...string) {
	t.Helper()

	for _, rootDir := range rootDirs {
		require.NoError(t, filepath.WalkDir(rootDir, func(filePath string, entry os.DirEntry, err error) error {
			require.NoError(t, err)
			require.Falsef(t, isRotationSentinel(entry.Name()), "rotation sentinel left behind: %s", filePath)

			return nil
		}))
	}
}
