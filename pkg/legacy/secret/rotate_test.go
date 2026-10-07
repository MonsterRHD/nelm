package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cgsecret "github.com/werf/common-go/pkg/secret"
)

type rtFixtureFile struct {
	relPath         string
	values          bool
	plainData       []byte
	mode            os.FileMode
	lineEnding      string
	trailingNewline bool
}

func rtWriteFixtureChart(t *testing.T, chartDir string, oldKey []byte, files []rtFixtureFile) map[string][]byte {
	t.Helper()

	encoder := rtTestEncoder(t, oldKey)
	plainByPath := map[string][]byte{}

	for _, fixtureFile := range files {
		filePath := filepath.Join(chartDir, fixtureFile.relPath)
		encrypted := rtEncrypt(t, encoder, fixtureFile.plainData, fixtureFile.values)

		if fixtureFile.lineEnding == "\r\n" {
			encrypted = bytes.ReplaceAll(encrypted, []byte("\n"), []byte("\r\n"))
		}

		if fixtureFile.trailingNewline {
			if !bytes.HasSuffix(encrypted, []byte(fixtureFile.lineEnding)) {
				encrypted = append(encrypted, fixtureFile.lineEnding...)
			}
		} else {
			encrypted = bytes.TrimRight(encrypted, "\r\n")
		}

		rtWriteFile(t, filePath, encrypted, fixtureFile.mode)
		plainByPath[filePath] = fixtureFile.plainData
	}

	return plainByPath
}

func rtAssertFilesReadableWithKey(t *testing.T, filePaths []string, key []byte, valuesByPath map[string]bool, expectReadable bool) {
	t.Helper()

	encoder := rtTestEncoder(t, key)

	for _, filePath := range filePaths {
		encrypted, err := os.ReadFile(filePath)
		require.NoError(t, err)

		var decryptErr error
		if valuesByPath[filePath] {
			_, decryptErr = encoder.DecryptYamlData(bytes.TrimSpace(encrypted))
		} else {
			_, decryptErr = encoder.Decrypt(bytes.TrimSpace(encrypted))
		}

		require.Equalf(t, expectReadable, decryptErr == nil, "file %q readable with key: %v", filePath, decryptErr)
	}
}

func TestRotateSecretKey_ReencryptsAllFiles(t *testing.T) {
	t.Chdir(t.TempDir())

	oldKey := rtTestSecretKey(t)
	newKey := rtTestSecretKey(t)
	rtSetKeys(t, oldKey, newKey)

	chartDir := filepath.Join(t.TempDir(), "chart")
	externalDir := t.TempDir()

	fixtureFiles := []rtFixtureFile{
		{relPath: DefaultSecretValuesFileName, values: true, plainData: []byte("foo: bar\n"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "db.txt"), values: false, plainData: []byte("db-password"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "config", "app.ini"), values: false, plainData: []byte("token = s3cr3t"), mode: 0o600, lineEnding: "\n", trailingNewline: true},
	}
	plainByPath := rtWriteFixtureChart(t, chartDir, oldKey, fixtureFiles)

	externalValuesPath := filepath.Join(externalDir, "external-secret-values.yaml")
	externalPlain := []byte("external: value\n")
	rtWriteFile(t, externalValuesPath, rtEncrypt(t, rtTestEncoder(t, oldKey), externalPlain, true), 0o644)
	plainByPath[externalValuesPath] = externalPlain

	rtRunRotate(t, chartDir, chartDir, externalValuesPath)

	var allPaths []string
	valuesByPath := map[string]bool{}
	for filePath := range plainByPath {
		allPaths = append(allPaths, filePath)
		valuesByPath[filePath] = filepath.Base(filePath) == DefaultSecretValuesFileName || filePath == externalValuesPath
	}

	newEncoder := rtTestEncoder(t, newKey)
	for _, filePath := range allPaths {
		encrypted, err := os.ReadFile(filePath)
		require.NoError(t, err)

		decrypted := rtDecrypt(t, newEncoder, encrypted, valuesByPath[filePath])
		require.Equalf(t, plainByPath[filePath], decrypted, "file %q plaintext changed", filePath)

		info, err := os.Stat(filePath)
		require.NoError(t, err)

		switch filepath.Base(filePath) {
		case "app.ini":
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "file %q permissions changed", filePath)
		default:
			require.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "file %q permissions changed", filePath)
		}
	}

	rtAssertFilesReadableWithKey(t, allPaths, oldKey, valuesByPath, false)
	rtAssertNoSentinels(t, chartDir, externalDir)
}

func TestRotateSecretKey_PreservesNewlineStyles(t *testing.T) {
	t.Chdir(t.TempDir())

	oldKey := rtTestSecretKey(t)
	newKey := rtTestSecretKey(t)
	rtSetKeys(t, oldKey, newKey)

	chartDir := filepath.Join(t.TempDir(), "chart")

	fixtureFiles := []rtFixtureFile{
		{relPath: DefaultSecretValuesFileName, values: true, plainData: []byte("foo: bar\n"), mode: 0o644, lineEnding: "\r\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "crlf.txt"), values: false, plainData: []byte("a"), mode: 0o644, lineEnding: "\r\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "nonewline.txt"), values: false, plainData: []byte("b"), mode: 0o644, lineEnding: "\n", trailingNewline: false},
		{relPath: filepath.Join(SecretDirName, "lf.txt"), values: false, plainData: []byte("c"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
	}
	plainByPath := rtWriteFixtureChart(t, chartDir, oldKey, fixtureFiles)

	rtRunRotate(t, chartDir, chartDir)

	newEncoder := rtTestEncoder(t, newKey)

	defaultValuesData, err := os.ReadFile(filepath.Join(chartDir, DefaultSecretValuesFileName))
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(defaultValuesData, []byte("\r\n")))
	require.NotContains(t, defaultValuesData, []byte("\r\n\n"))
	require.Equal(t, bytes.Count(defaultValuesData, []byte("\n")), bytes.Count(defaultValuesData, []byte("\r\n")))
	require.Equal(t, plainByPath[filepath.Join(chartDir, DefaultSecretValuesFileName)], rtDecrypt(t, newEncoder, defaultValuesData, true))

	crlfData, err := os.ReadFile(filepath.Join(chartDir, SecretDirName, "crlf.txt"))
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(crlfData, []byte("\r\n")))

	noNewlineData, err := os.ReadFile(filepath.Join(chartDir, SecretDirName, "nonewline.txt"))
	require.NoError(t, err)
	require.False(t, bytes.HasSuffix(noNewlineData, []byte("\n")))
	require.Equal(t, plainByPath[filepath.Join(chartDir, SecretDirName, "nonewline.txt")], rtDecrypt(t, newEncoder, noNewlineData, false))

	lfData, err := os.ReadFile(filepath.Join(chartDir, SecretDirName, "lf.txt"))
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(lfData, []byte("\n")))
	require.False(t, bytes.HasSuffix(lfData, []byte("\r\n")))

	rtAssertNoSentinels(t, chartDir)
}

func TestRotateSecretKey_SameKeyKeepsFilesReadable(t *testing.T) {
	t.Chdir(t.TempDir())

	key := rtTestSecretKey(t)
	rtSetKeys(t, key, key)

	chartDir := filepath.Join(t.TempDir(), "chart")
	fixtureFiles := []rtFixtureFile{
		{relPath: DefaultSecretValuesFileName, values: true, plainData: []byte("foo: bar\n"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "db.txt"), values: false, plainData: []byte("db-password"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
	}
	plainByPath := rtWriteFixtureChart(t, chartDir, key, fixtureFiles)

	rtRunRotate(t, chartDir, chartDir)

	for filePath, plainData := range plainByPath {
		encrypted, err := os.ReadFile(filePath)
		require.NoError(t, err)

		decrypted := rtDecrypt(t, rtTestEncoder(t, key), encrypted, filepath.Base(filePath) == DefaultSecretValuesFileName)
		require.Equal(t, plainData, decrypted)
	}

	rtAssertNoSentinels(t, chartDir)
}

func TestRotateSecretKey_MissingOptionalPaths(t *testing.T) {
	t.Chdir(t.TempDir())

	oldKey := rtTestSecretKey(t)
	newKey := rtTestSecretKey(t)
	rtSetKeys(t, oldKey, newKey)

	t.Run("explicit values without chart directory", func(t *testing.T) {
		externalDir := t.TempDir()
		externalPath := filepath.Join(externalDir, "secret-values.yaml")
		plain := []byte("foo: bar\n")
		rtWriteFile(t, externalPath, rtEncrypt(t, rtTestEncoder(t, oldKey), plain, true), 0o644)

		rtRunRotate(t, filepath.Join(t.TempDir(), "missing-chart"), externalDir, externalPath)

		require.Equal(t, plain, rtDecrypt(t, rtTestEncoder(t, newKey), mustReadFile(t, externalPath), true))
		rtAssertNoSentinels(t, externalDir)
	})

	t.Run("chart directory without secret files", func(t *testing.T) {
		emptyChartDir := t.TempDir()
		rtRunRotate(t, emptyChartDir, emptyChartDir)
		rtAssertNoSentinels(t, emptyChartDir)
	})

	t.Run("missing explicit values file", func(t *testing.T) {
		chartDir := t.TempDir()
		missingPath := filepath.Join(t.TempDir(), "missing-secret-values.yaml")

		err := RotateSecretKey(context.Background(), chartDir, chartDir, missingPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stat secret file")
		rtAssertNoSentinels(t, chartDir)
	})
}

func TestRotateSecretKey_WrongOldKeyRestoresFiles(t *testing.T) {
	t.Chdir(t.TempDir())

	oldKey := rtTestSecretKey(t)
	wrongOldKey := rtTestSecretKey(t)
	newKey := rtTestSecretKey(t)
	rtSetKeys(t, wrongOldKey, newKey)

	chartDir := filepath.Join(t.TempDir(), "chart")
	fixtureFiles := []rtFixtureFile{
		{relPath: DefaultSecretValuesFileName, values: true, plainData: []byte("foo: bar\n"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "db.txt"), values: false, plainData: []byte("db-password"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
	}
	plainByPath := rtWriteFixtureChart(t, chartDir, oldKey, fixtureFiles)

	originalData := map[string][]byte{}
	for filePath := range plainByPath {
		originalData[filePath] = mustReadFile(t, filePath)
	}

	err := RotateSecretKey(context.Background(), chartDir, chartDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt with old key")

	for filePath, data := range originalData {
		require.Equal(t, data, mustReadFile(t, filePath), "file %q modified by failed rotation", filePath)
		require.Equal(t, plainByPath[filePath], rtDecrypt(t, rtTestEncoder(t, oldKey), data, filepath.Base(filePath) == DefaultSecretValuesFileName))
	}

	rtAssertNoSentinels(t, chartDir)
}

func TestRotateSecretKey_DeduplicatesExplicitDefaultFile(t *testing.T) {
	t.Chdir(t.TempDir())

	oldKey := rtTestSecretKey(t)

	chartDir := filepath.Join(t.TempDir(), "chart")
	defaultPath := filepath.Join(chartDir, DefaultSecretValuesFileName)
	rtWriteFile(t, defaultPath, rtEncrypt(t, rtTestEncoder(t, oldKey), []byte("foo: bar\n"), true), 0o644)

	plan, err := buildRotationPlan(chartDir, []string{defaultPath}, true)
	require.NoError(t, err)
	require.Len(t, plan.files, 1)
}

func TestAssertSecretFilesUnchanged_RejectsModifications(t *testing.T) {
	t.Chdir(t.TempDir())

	chartDir := filepath.Join(t.TempDir(), "chart")
	filePath := filepath.Join(chartDir, SecretDirName, "db.txt")
	rtWriteFile(t, filePath, []byte("old-bytes"), 0o644)

	plan, err := buildRotationPlan(chartDir, nil, true)
	require.NoError(t, err)
	require.Len(t, plan.files, 1)

	frozen, err := freezeSecretFiles(plan.files)
	require.NoError(t, err)

	require.NoError(t, assertSecretFilesUnchanged(frozen))

	require.NoError(t, os.WriteFile(filePath, []byte("new-bytes"), 0o644))
	err = assertSecretFilesUnchanged(frozen)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "was modified during key rotation")
}

func TestRotateSecretKey_CompletesAfterInterruptedCandidates(t *testing.T) {
	t.Chdir(t.TempDir())

	oldKey := rtTestSecretKey(t)
	newKey := rtTestSecretKey(t)
	rtSetKeys(t, oldKey, newKey)

	chartDir := filepath.Join(t.TempDir(), "chart")
	fixtureFiles := []rtFixtureFile{
		{relPath: DefaultSecretValuesFileName, values: true, plainData: []byte("foo: bar\n"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "db.txt"), values: false, plainData: []byte("db-password"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
	}
	plainByPath := rtWriteFixtureChart(t, chartDir, oldKey, fixtureFiles)

	newEncoder := rtTestEncoder(t, newKey)
	for filePath := range plainByPath {
		isValues := filepath.Base(filePath) == DefaultSecretValuesFileName
		candidatePath := filePath + rotateCandidateSuffix
		rtWriteFile(t, candidatePath, rtEncrypt(t, newEncoder, plainByPath[filePath], isValues), 0o644)
	}

	rtRunRotate(t, chartDir, chartDir)

	for filePath, plainData := range plainByPath {
		isValues := filepath.Base(filePath) == DefaultSecretValuesFileName
		require.Equal(t, plainData, rtDecrypt(t, newEncoder, mustReadFile(t, filePath), isValues))
	}

	rtAssertNoSentinels(t, chartDir)
}

func TestRotateSecretKey_RecoversInterruptedSwitch(t *testing.T) {
	t.Chdir(t.TempDir())

	oldKey := rtTestSecretKey(t)
	newKey := rtTestSecretKey(t)
	rtSetKeys(t, oldKey, newKey)

	chartDir := filepath.Join(t.TempDir(), "chart")
	fixtureFiles := []rtFixtureFile{
		{relPath: DefaultSecretValuesFileName, values: true, plainData: []byte("foo: bar\n"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "db.txt"), values: false, plainData: []byte("db-password"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
		{relPath: filepath.Join(SecretDirName, "untouched.txt"), values: false, plainData: []byte("untouched"), mode: 0o644, lineEnding: "\n", trailingNewline: true},
	}
	plainByPath := rtWriteFixtureChart(t, chartDir, oldKey, fixtureFiles)

	oldEncoder := rtTestEncoder(t, oldKey)
	newEncoder := rtTestEncoder(t, newKey)

	missingPath := filepath.Join(chartDir, DefaultSecretValuesFileName)
	rtWriteInterruptedSwitch(t, missingPath, plainByPath[missingPath], true, oldEncoder, newEncoder)

	switchedPath := filepath.Join(chartDir, SecretDirName, "db.txt")
	rtWritePostSwitchCrash(t, switchedPath, plainByPath[switchedPath], false, oldEncoder, newEncoder)

	rtRunRotate(t, chartDir, chartDir)

	allPaths := rtMapKeys(plainByPath)
	valuesByPath := map[string]bool{}
	for filePath, plainData := range plainByPath {
		isValues := filepath.Base(filePath) == DefaultSecretValuesFileName
		valuesByPath[filePath] = isValues
		require.Equalf(t, plainData, rtDecrypt(t, newEncoder, mustReadFile(t, filePath), isValues), "file %q not re-encrypted with new key", filePath)
	}

	rtAssertFilesReadableWithKey(t, allPaths, oldKey, valuesByPath, false)
	rtAssertNoSentinels(t, chartDir)
}

func TestRecoverInterruptedRotation_RestoresStateListedExternalFile(t *testing.T) {
	t.Chdir(t.TempDir())

	oldKey := rtTestSecretKey(t)
	rtSetKeys(t, oldKey, rtTestSecretKey(t))

	chartDir := filepath.Join(t.TempDir(), "chart")
	require.NoError(t, os.MkdirAll(chartDir, 0o755))

	externalDir := t.TempDir()
	externalPath := filepath.Join(externalDir, "external-secret-values.yaml")
	plain := []byte("external: value\n")
	oldEncrypted := rtEncrypt(t, rtTestEncoder(t, oldKey), plain, true)

	rtWriteFile(t, externalPath+rotateBackupSuffix, oldEncrypted, 0o644)
	rtWriteFile(t, externalPath+rotateCandidateSuffix, rtEncrypt(t, rtTestEncoder(t, rtTestSecretKey(t)), plain, true), 0o644)

	plan, err := buildRotationPlan(chartDir, nil, false)
	require.NoError(t, err)

	state := rotationStateData{
		Version: rotateStateFileVersion,
		Files:   []rotationStateFile{{Path: externalPath, Values: true}},
	}
	stateData, err := json.MarshalIndent(&state, "", "  ")
	require.NoError(t, err)
	rtWriteFile(t, filepath.Join(chartDir, rotateStateFileName), stateData, 0o600)

	require.NoError(t, recoverInterruptedRotation(context.Background(), plan, rtTestEncoder(t, oldKey)))

	_, err = os.Stat(externalPath)
	require.NoError(t, err)
	require.Equal(t, plain, rtDecrypt(t, rtTestEncoder(t, oldKey), mustReadFile(t, externalPath), true))
	rtAssertNoSentinels(t, chartDir, externalDir)
}

func TestRecoverInterruptedRotation_CommittedBackupLeftover(t *testing.T) {
	t.Chdir(t.TempDir())

	key := rtTestSecretKey(t)
	encoder := rtTestEncoder(t, key)

	chartDir := filepath.Join(t.TempDir(), "chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, SecretDirName), 0o755))

	targetPath := filepath.Join(chartDir, SecretDirName, "db.txt")
	encrypted := rtEncrypt(t, encoder, []byte("db-password"), false)
	rtWriteFile(t, targetPath, encrypted, 0o644)
	rtWriteFile(t, targetPath+rotateBackupSuffix, encrypted, 0o644)

	plan, err := buildRotationPlan(chartDir, nil, false)
	require.NoError(t, err)

	require.NoError(t, recoverInterruptedRotation(context.Background(), plan, encoder))

	require.Equal(t, encrypted, mustReadFile(t, targetPath))
	_, err = os.Stat(targetPath + rotateBackupSuffix)
	require.True(t, os.IsNotExist(err))
	rtAssertNoSentinels(t, chartDir)
}

func TestWithRotationLock_BlocksSecondHolder(t *testing.T) {
	t.Chdir(t.TempDir())

	anchorDir := t.TempDir()

	err := withRotationLock(context.Background(), anchorDir, func() error {
		return withRotationLock(context.Background(), anchorDir, func() error {
			t.Fatal("nested rotation lock must not be acquired")

			return nil
		})
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, errRotationLockBusy)

	lockPath := filepath.Join(anchorDir, rotateLockFileName)
	_, err = os.Stat(lockPath)
	require.True(t, os.IsNotExist(err), "lock file must be removed after release")
}

func rtWriteInterruptedSwitch(t *testing.T, targetPath string, plainData []byte, values bool, oldEncoder, newEncoder *cgsecret.YamlEncoder) {
	t.Helper()

	oldEncrypted := rtEncrypt(t, oldEncoder, plainData, values)
	newEncrypted := rtEncrypt(t, newEncoder, plainData, values)

	rtWriteFile(t, targetPath+rotateBackupSuffix, oldEncrypted, 0o644)
	rtWriteFile(t, targetPath+rotateCandidateSuffix, newEncrypted, 0o644)
}

func rtWritePostSwitchCrash(t *testing.T, targetPath string, plainData []byte, values bool, oldEncoder, newEncoder *cgsecret.YamlEncoder) {
	t.Helper()

	rtWriteFile(t, targetPath, rtEncrypt(t, newEncoder, plainData, values), 0o644)
	rtWriteFile(t, targetPath+rotateBackupSuffix, rtEncrypt(t, oldEncoder, plainData, values), 0o644)
}

func mustReadFile(t *testing.T, filePath string) []byte {
	t.Helper()

	data, err := os.ReadFile(filePath)
	require.NoError(t, err)

	return data
}

func rtMapKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
