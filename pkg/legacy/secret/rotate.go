package secret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/samber/lo"

	"github.com/werf/common-go/pkg/secret"
	"github.com/werf/common-go/pkg/secrets_manager"
	"github.com/werf/common-go/pkg/util"
	"github.com/werf/nelm/v2/pkg/log"
	nelmutil "github.com/werf/nelm/v2/pkg/util"
)

const (
	rotateStateFileName   = ".nelm-secret-key-rotate.state"
	rotateLockFileName    = ".nelm-secret-key-rotate.lock"
	rotateCandidateSuffix = ".nelm-secret-key-rotate.new"
	rotateBackupSuffix    = ".nelm-secret-key-rotate.old"

	rotateStateFileVersion = 1
)

type rotationPlan struct {
	anchorDir     string
	chartDir      string
	secretDir     string
	explicitPaths []string
	files         []rotationTarget
}

type rotationTarget struct {
	path        string
	displayPath string
	values      bool
}

type frozenSecretFile struct {
	target          rotationTarget
	mode            os.FileMode
	modTime         time.Time
	size            int64
	hash            [sha256.Size]byte
	raw             []byte
	lineEnding      string
	trailingNewline bool
	encrypted       []byte
}

func (f *frozenSecretFile) candidatePath() string {
	return f.target.path + rotateCandidateSuffix
}

func (f *frozenSecretFile) backupPath() string {
	return f.target.path + rotateBackupSuffix
}

type rotationStateData struct {
	Version int                 `json:"version"`
	Files   []rotationStateFile `json:"files"`
}

type rotationStateFile struct {
	Path   string `json:"path"`
	Values bool   `json:"values"`
}

func RotateSecretKey(ctx context.Context, helmChartDir, secretWorkingDir string, secretValuesPaths ...string) error {
	secretsManager := secrets_manager.Manager

	newEncoder, err := secretsManager.GetYamlEncoder(ctx, secretWorkingDir, false)
	if err != nil {
		return err
	}

	oldEncoder, err := secretsManager.GetYamlEncoderForOldKey(ctx)
	if err != nil {
		return err
	}

	plan, err := buildRotationPlan(helmChartDir, secretValuesPaths, false)
	if err != nil {
		return err
	}

	if _, err := os.Stat(plan.anchorDir); err != nil {
		return fmt.Errorf("access secret key rotation directory %q: %w", plan.anchorDir, err)
	}

	return withRotationLock(ctx, plan.anchorDir, func() error {
		return rotateSecretFiles(ctx, helmChartDir, secretValuesPaths, oldEncoder, newEncoder)
	})
}

func withRotationLock(ctx context.Context, anchorDir string, fn func() error) error {
	lockPath := filepath.Join(anchorDir, rotateLockFileName)

	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open secret key rotation lock file %q: %w", lockPath, err)
	}

	if err := lockFile(file); err != nil {
		_ = file.Close()

		if errors.Is(err, errRotationLockBusy) {
			return fmt.Errorf("%w for directory %q, wait for it to finish or stop that process", err, anchorDir)
		}

		return fmt.Errorf("acquire secret key rotation lock %q: %w", lockPath, err)
	}

	runErr := fn()

	if err := unlockFile(file); err != nil {
		log.Default.Warn(ctx, "Unable to release secret key rotation lock %q: %s", lockPath, err)
	}

	if err := file.Close(); err != nil {
		log.Default.Warn(ctx, "Unable to close secret key rotation lock file %q: %s", lockPath, err)
	}

	if err := os.Remove(lockPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Default.Warn(ctx, "Unable to remove secret key rotation lock file %q: %s", lockPath, err)
	}

	return runErr
}

func rotateSecretFiles(ctx context.Context, helmChartDir string, secretValuesPaths []string, oldEncoder, newEncoder *secret.YamlEncoder) error {
	plan, err := buildRotationPlan(helmChartDir, secretValuesPaths, false)
	if err != nil {
		return err
	}

	if err := recoverInterruptedRotation(ctx, plan, oldEncoder); err != nil {
		return fmt.Errorf("recover interrupted secret key rotation: %w", err)
	}

	plan, err = buildRotationPlan(helmChartDir, secretValuesPaths, true)
	if err != nil {
		return err
	}

	if len(plan.files) == 0 {
		return nil
	}

	files, err := freezeSecretFiles(plan.files)
	if err != nil {
		return err
	}

	if err := writeRotationState(plan.anchorDir, files); err != nil {
		return err
	}

	failed := true
	defer func() {
		if failed {
			if err := rollbackSecretFiles(ctx, files); err != nil {
				log.Default.Error(ctx, "Unable to fully restore secret files after failed key rotation: %s", err)
				return
			}

			if err := removeRotationState(plan.anchorDir); err != nil {
				log.Default.Error(ctx, "Unable to remove key rotation state file: %s", err)
			}
		}
	}()

	if err := regenerateSecretFiles(ctx, files, oldEncoder, newEncoder); err != nil {
		return err
	}

	if err := writeRotationCandidates(ctx, files); err != nil {
		return err
	}

	if err := assertSecretFilesUnchanged(files); err != nil {
		return err
	}

	if err := switchSecretFiles(ctx, files); err != nil {
		return fmt.Errorf("switch re-encrypted secret files: %w", err)
	}

	for _, frozenFile := range files {
		if err := os.Remove(frozenFile.backupPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Default.Warn(ctx, "Rotation finished, but unable to remove backup file %q: %s. It will be cleaned up on the next rotation.", frozenFile.backupPath(), err)
		} else {
			if err := syncDir(filepath.Dir(frozenFile.target.path)); err != nil {
				log.Default.Warn(ctx, "Unable to sync directory %q after removing backup: %s", filepath.Dir(frozenFile.target.path), err)
			}
		}
	}

	if err := removeRotationState(plan.anchorDir); err != nil {
		log.Default.Warn(ctx, "Rotation finished, but unable to remove state file %q: %s. It will be cleaned up on the next rotation.", filepath.Join(plan.anchorDir, rotateStateFileName), err)
	}

	failed = false

	return nil
}

func buildRotationPlan(helmChartDir string, secretValuesPaths []string, strict bool) (*rotationPlan, error) {
	plan := &rotationPlan{}

	for _, filePath := range secretValuesPaths {
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			return nil, fmt.Errorf("get absolute path of secret values file %q: %w", filePath, err)
		}

		plan.explicitPaths = append(plan.explicitPaths, absPath)
		plan.anchorDir = filepath.Dir(absPath)
	}

	if helmChartDir != "" {
		absChartDir, err := filepath.Abs(helmChartDir)
		if err != nil {
			return nil, fmt.Errorf("get absolute path of chart directory %q: %w", helmChartDir, err)
		}

		if info, err := os.Stat(absChartDir); err == nil && info.IsDir() {
			plan.chartDir = absChartDir
			plan.secretDir = filepath.Join(absChartDir, SecretDirName)
			plan.anchorDir = absChartDir
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("stat chart directory %q: %w", absChartDir, err)
		}
	}

	if plan.anchorDir == "" {
		currentDir, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("get current working directory: %w", err)
		}

		plan.anchorDir = currentDir
	}

	if !strict {
		return plan, nil
	}

	seenPaths := map[string]struct{}{}
	addFile := func(filePath string, values bool) error {
		if _, ok := seenPaths[filePath]; ok {
			return nil
		}

		info, err := os.Stat(filePath)
		if err != nil {
			return fmt.Errorf("stat secret file %q: %w", filePath, err)
		}

		if !info.Mode().IsRegular() {
			return fmt.Errorf("secret file %q is not a regular file", filePath)
		}

		seenPaths[filePath] = struct{}{}
		plan.files = append(plan.files, rotationTarget{path: filePath, values: values})

		return nil
	}

	for _, filePath := range plan.explicitPaths {
		if err := addFile(filePath, true); err != nil {
			return nil, err
		}
	}

	if plan.chartDir != "" {
		defaultSecretValuesPath := filepath.Join(plan.chartDir, DefaultSecretValuesFileName)
		defaultExists, err := util.RegularFileExists(defaultSecretValuesPath)
		if err != nil {
			return nil, fmt.Errorf("check default secret values file %q: %w", defaultSecretValuesPath, err)
		}

		if defaultExists {
			if err := addFile(defaultSecretValuesPath, true); err != nil {
				return nil, err
			}
		}

		if info, err := os.Stat(plan.secretDir); err == nil && info.IsDir() {
			err := filepath.WalkDir(plan.secretDir, func(filePath string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}

				if entry.IsDir() || isRotationSentinel(entry.Name()) {
					return nil
				}

				info, err := os.Stat(filePath)
				if err != nil {
					return err
				}

				if !info.Mode().IsRegular() {
					return nil
				}

				return addFile(filePath, false)
			})
			if err != nil {
				return nil, fmt.Errorf("collect files of secret directory %q: %w", plan.secretDir, err)
			}
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("stat secret directory %q: %w", plan.secretDir, err)
		}
	}

	sort.Slice(plan.files, func(i, j int) bool {
		return plan.files[i].path < plan.files[j].path
	})

	for i := range plan.files {
		plan.files[i].displayPath = displayPath(plan.files[i].path)
	}

	return plan, nil
}

func displayPath(absPath string) string {
	pwd, err := os.Getwd()
	if err != nil {
		return absPath
	}

	relPath, err := filepath.Rel(pwd, absPath)
	if err != nil {
		return absPath
	}

	return relPath
}

func isRotationSentinel(name string) bool {
	return name == rotateStateFileName ||
		name == rotateLockFileName ||
		strings.HasSuffix(name, rotateCandidateSuffix) ||
		strings.HasSuffix(name, rotateBackupSuffix)
}

func freezeSecretFiles(targets []rotationTarget) ([]*frozenSecretFile, error) {
	files := make([]*frozenSecretFile, 0, len(targets))

	for _, target := range targets {
		raw, info, err := readFileWithInfo(target.path)
		if err != nil {
			return nil, err
		}

		files = append(files, &frozenSecretFile{
			target:          target,
			mode:            info.Mode(),
			modTime:         info.ModTime(),
			size:            info.Size(),
			hash:            sha256.Sum256(raw),
			raw:             raw,
			lineEnding:      lo.Ternary(bytes.Contains(raw, []byte("\r\n")), "\r\n", "\n"),
			trailingNewline: len(raw) > 0 && raw[len(raw)-1] == '\n',
		})
	}

	return files, nil
}

func readFileWithInfo(filePath string) ([]byte, fs.FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("stat secret file %q: %w", filePath, err)
	}

	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read secret file %q: %w", filePath, err)
	}

	return raw, info, nil
}

func regenerateSecretFiles(ctx context.Context, files []*frozenSecretFile, oldEncoder, newEncoder *secret.YamlEncoder) error {
	for _, frozenFile := range files {
		if err := log.Default.InfoBlockErr(ctx, log.BlockOptions{
			BlockTitle: fmt.Sprintf("Regenerating file %q", frozenFile.target.displayPath),
		}, func() error {
			trimmed := bytes.TrimSpace(frozenFile.raw)

			var plainData, encryptedData []byte
			var err error
			if frozenFile.target.values {
				plainData, err = oldEncoder.DecryptYamlData(trimmed)
				if err != nil {
					return fmt.Errorf("decrypt with old key: %w", err)
				}

				encryptedData, err = newEncoder.EncryptYamlData(plainData)
				if err != nil {
					return fmt.Errorf("encrypt with new key: %w", err)
				}

				readbackData, err := newEncoder.DecryptYamlData(encryptedData)
				if err != nil {
					return fmt.Errorf("verify re-encrypted file with new key: %w", err)
				}

				if !bytes.Equal(readbackData, plainData) {
					return fmt.Errorf("verify re-encrypted file with new key: decrypted data does not match the original data")
				}
			} else {
				plainData, err = oldEncoder.Decrypt(trimmed)
				if err != nil {
					return fmt.Errorf("decrypt with old key: %w", err)
				}

				encryptedData, err = newEncoder.Encrypt(plainData)
				if err != nil {
					return fmt.Errorf("encrypt with new key: %w", err)
				}

				readbackData, err := newEncoder.Decrypt(encryptedData)
				if err != nil {
					return fmt.Errorf("verify re-encrypted file with new key: %w", err)
				}

				if !bytes.Equal(readbackData, plainData) {
					return fmt.Errorf("verify re-encrypted file with new key: decrypted data does not match the original data")
				}
			}

			frozenFile.encrypted = applyNewlineStyle(encryptedData, frozenFile)

			return nil
		}); err != nil {
			return err
		}
	}

	return nil
}

func applyNewlineStyle(data []byte, frozenFile *frozenSecretFile) []byte {
	result := bytes.TrimRight(data, "\r\n")

	if frozenFile.lineEnding == "\r\n" {
		result = bytes.ReplaceAll(result, []byte("\n"), []byte("\r\n"))
	}

	if frozenFile.trailingNewline {
		result = append(result, frozenFile.lineEnding...)
	}

	return result
}

func writeRotationCandidates(ctx context.Context, files []*frozenSecretFile) error {
	for _, frozenFile := range files {
		if err := log.Default.InfoBlockErr(ctx, log.BlockOptions{
			BlockTitle: fmt.Sprintf("Preparing file %q", frozenFile.target.displayPath),
		}, func() error {
			return writeFileSync(frozenFile.candidatePath(), frozenFile.encrypted, frozenFile.mode)
		}); err != nil {
			return err
		}

		if err := syncDir(filepath.Dir(frozenFile.target.path)); err != nil {
			return fmt.Errorf("sync directory %q: %w", filepath.Dir(frozenFile.target.path), err)
		}
	}

	return nil
}

func writeFileSync(filePath string, data []byte, mode os.FileMode) (err error) {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return fmt.Errorf("create file %q: %w", filePath, err)
	}

	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close file %q: %w", filePath, closeErr)
		}
	}()

	if err := file.Chmod(mode.Perm()); err != nil {
		return fmt.Errorf("set permissions of file %q: %w", filePath, err)
	}

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write file %q: %w", filePath, err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync file %q: %w", filePath, err)
	}

	return nil
}

func assertSecretFilesUnchanged(files []*frozenSecretFile) error {
	for _, frozenFile := range files {
		raw, _, err := readFileWithInfo(frozenFile.target.path)
		if err != nil {
			return err
		}

		if sha256.Sum256(raw) != frozenFile.hash {
			return fmt.Errorf("secret file %q was modified during key rotation, refusing to overwrite it", frozenFile.target.displayPath)
		}
	}

	return nil
}

func switchSecretFiles(ctx context.Context, files []*frozenSecretFile) error {
	for _, frozenFile := range files {
		if err := log.Default.InfoBlockErr(ctx, log.BlockOptions{
			BlockTitle: fmt.Sprintf("Saving file %q", frozenFile.target.displayPath),
		}, func() error {
			info, err := os.Stat(frozenFile.target.path)
			if err != nil {
				return fmt.Errorf("stat secret file %q: %w", frozenFile.target.displayPath, err)
			}

			if info.Size() != frozenFile.size || !info.ModTime().Equal(frozenFile.modTime) {
				return fmt.Errorf("secret file %q was modified during key rotation, refusing to overwrite it", frozenFile.target.displayPath)
			}

			if err := os.Rename(frozenFile.target.path, frozenFile.backupPath()); err != nil {
				return fmt.Errorf("move file %q to backup: %w", frozenFile.target.displayPath, err)
			}

			if err := os.Rename(frozenFile.candidatePath(), frozenFile.target.path); err != nil {
				return fmt.Errorf("move new version of file %q into place: %w", frozenFile.target.displayPath, err)
			}

			return nil
		}); err != nil {
			return err
		}

		if err := syncDir(filepath.Dir(frozenFile.target.path)); err != nil {
			return fmt.Errorf("sync directory %q: %w", filepath.Dir(frozenFile.target.path), err)
		}
	}

	return nil
}

func rollbackSecretFiles(ctx context.Context, files []*frozenSecretFile) error {
	errs := &nelmutil.MultiError{}
	syncedDirs := map[string]struct{}{}

	for _, frozenFile := range files {
		if _, err := os.Stat(frozenFile.backupPath()); err == nil {
			if err := os.Rename(frozenFile.backupPath(), frozenFile.target.path); err != nil {
				errs.Add(fmt.Errorf("restore file %q from backup: %w", frozenFile.target.displayPath, err))
			} else {
				syncedDirs[filepath.Dir(frozenFile.target.path)] = struct{}{}
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			errs.Add(fmt.Errorf("stat backup of file %q: %w", frozenFile.target.displayPath, err))
		}

		if err := os.Remove(frozenFile.candidatePath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs.Add(fmt.Errorf("remove candidate file %q: %w", frozenFile.candidatePath(), err))
		}
	}

	for dirPath := range syncedDirs {
		if err := syncDir(dirPath); err != nil {
			errs.Add(fmt.Errorf("sync directory %q: %w", dirPath, err))
		}
	}

	if err := errs.OrNilIfNoErrs(); err != nil {
		return fmt.Errorf("restore old secret files: %w", err)
	}

	log.Default.Info(ctx, "All secret files were restored with the old encryption key")

	return nil
}

func writeRotationState(anchorDir string, files []*frozenSecretFile) error {
	state := rotationStateData{Version: rotateStateFileVersion}
	state.Files = make([]rotationStateFile, 0, len(files))

	for _, frozenFile := range files {
		state.Files = append(state.Files, rotationStateFile{
			Path:   frozenFile.target.path,
			Values: frozenFile.target.values,
		})
	}

	data, err := json.MarshalIndent(&state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key rotation state: %w", err)
	}

	statePath := filepath.Join(anchorDir, rotateStateFileName)
	tempStatePath := statePath + rotateCandidateSuffix

	if err := writeFileSync(tempStatePath, data, 0o600); err != nil {
		return fmt.Errorf("write key rotation state file %q: %w", statePath, err)
	}

	if err := os.Rename(tempStatePath, statePath); err != nil {
		_ = os.Remove(tempStatePath)

		return fmt.Errorf("move key rotation state file into place %q: %w", statePath, err)
	}

	if err := syncDir(anchorDir); err != nil {
		return fmt.Errorf("sync directory %q: %w", anchorDir, err)
	}

	return nil
}

func removeRotationState(anchorDir string) error {
	statePath := filepath.Join(anchorDir, rotateStateFileName)
	if err := os.Remove(statePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove key rotation state file %q: %w", statePath, err)
	}

	if err := syncDir(anchorDir); err != nil {
		return fmt.Errorf("sync directory %q: %w", anchorDir, err)
	}

	return nil
}

func readRotationState(anchorDir string) (*rotationStateData, error) {
	statePath := filepath.Join(anchorDir, rotateStateFileName)

	data, err := os.ReadFile(statePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("read key rotation state file %q: %w", statePath, err)
	}

	var state rotationStateData
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse key rotation state file %q: %w", statePath, err)
	}

	return &state, nil
}

func recoverInterruptedRotation(ctx context.Context, plan *rotationPlan, oldEncoder *secret.YamlEncoder) error {
	state, err := readRotationState(plan.anchorDir)
	if err != nil {
		return err
	}

	targets := map[string]struct{}{}
	if state != nil {
		for _, stateFile := range state.Files {
			targets[stateFile.Path] = struct{}{}
		}
	}

	sweepDirs, err := rotationSweepDirs(plan)
	if err != nil {
		return err
	}

	for dirPath := range sweepDirs {
		if err := collectRotationSentinels(dirPath, targets); err != nil {
			return err
		}
	}

	if len(targets) == 0 {
		if state != nil {
			return removeRotationState(plan.anchorDir)
		}

		return nil
	}

	log.Default.Info(ctx, "Found an unfinished secret key rotation, restoring %d secret file(s) with the old encryption key", len(targets))

	sortedTargets := lo.Keys(targets)
	sort.Strings(sortedTargets)

	errs := &nelmutil.MultiError{}
	syncedDirs := map[string]struct{}{}

	for _, targetPath := range sortedTargets {
		backupPath := targetPath + rotateBackupSuffix
		candidatePath := targetPath + rotateCandidateSuffix

		backupExists, err := util.RegularFileExists(backupPath)
		if err != nil {
			errs.Add(fmt.Errorf("check backup file %q: %w", backupPath, err))
			continue
		}

		candidateExists, err := util.RegularFileExists(candidatePath)
		if err != nil {
			errs.Add(fmt.Errorf("check candidate file %q: %w", candidatePath, err))
			continue
		}

		switch {
		case !backupExists:
			if candidateExists {
				if err := os.Remove(candidatePath); err != nil {
					errs.Add(fmt.Errorf("remove candidate file %q: %w", candidatePath, err))
				}
			}
		case candidateExists:
			if err := os.Rename(backupPath, targetPath); err != nil {
				errs.Add(fmt.Errorf("restore file %q from backup: %w", targetPath, err))
			} else {
				syncedDirs[filepath.Dir(targetPath)] = struct{}{}
			}

			if err := os.Remove(candidatePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs.Add(fmt.Errorf("remove candidate file %q: %w", candidatePath, err))
			}
		default:
			readable, err := fileReadableWithKey(targetPath, oldEncoder)
			if err != nil {
				errs.Add(err)
				continue
			}

			if readable {
				if err := os.Remove(backupPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
					errs.Add(fmt.Errorf("remove stale backup file %q: %w", backupPath, err))
				}
			} else {
				if err := os.Rename(backupPath, targetPath); err != nil {
					errs.Add(fmt.Errorf("restore file %q from backup: %w", targetPath, err))
				} else {
					syncedDirs[filepath.Dir(targetPath)] = struct{}{}
				}
			}
		}
	}

	for dirPath := range syncedDirs {
		if err := syncDir(dirPath); err != nil {
			errs.Add(fmt.Errorf("sync directory %q: %w", dirPath, err))
		}
	}

	if err := errs.OrNilIfNoErrs(); err != nil {
		return err
	}

	return removeRotationState(plan.anchorDir)
}

func rotationSweepDirs(plan *rotationPlan) (map[string]struct{}, error) {
	dirs := map[string]struct{}{plan.anchorDir: {}}

	for _, explicitPath := range plan.explicitPaths {
		dirs[filepath.Dir(explicitPath)] = struct{}{}
	}

	if plan.secretDir != "" {
		if info, err := os.Stat(plan.secretDir); err == nil && info.IsDir() {
			err := filepath.WalkDir(plan.secretDir, func(dirPath string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}

				if entry.IsDir() && !isRotationSentinel(entry.Name()) {
					dirs[dirPath] = struct{}{}
				}

				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("scan secret directory %q: %w", plan.secretDir, err)
			}
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("stat secret directory %q: %w", plan.secretDir, err)
		}
	}

	return dirs, nil
}

func collectRotationSentinels(dirPath string, targets map[string]struct{}) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("read directory %q: %w", dirPath, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()

		if strings.HasSuffix(name, rotateBackupSuffix) {
			targets[filepath.Join(dirPath, strings.TrimSuffix(name, rotateBackupSuffix))] = struct{}{}
		}

		if strings.HasSuffix(name, rotateCandidateSuffix) {
			targets[filepath.Join(dirPath, strings.TrimSuffix(name, rotateCandidateSuffix))] = struct{}{}
		}
	}

	return nil
}

func fileReadableWithKey(filePath string, encoder *secret.YamlEncoder) (bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		return false, fmt.Errorf("read secret file %q: %w", filePath, err)
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return true, nil
	}

	if _, err := encoder.Decrypt(data); err == nil {
		return true, nil
	}

	if _, err := encoder.DecryptYamlData(data); err == nil {
		return true, nil
	}

	return false, nil
}
