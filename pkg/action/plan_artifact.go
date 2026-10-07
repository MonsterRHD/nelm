package action

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/samber/lo"

	"github.com/werf/common-go/pkg/secrets_manager"
	"github.com/werf/nelm/v2/pkg/common"
	"github.com/werf/nelm/v2/pkg/log"
	"github.com/werf/nelm/v2/pkg/plan"
	"github.com/werf/nelm/v2/pkg/release"
)

const PlanArtifactSchemeVersion = "v2"

type PlanArtifact struct {
	APIVersion string              `json:"apiVersion"`
	Data       *PlanArtifactData   `json:"-"`
	DataRaw    string              `json:"dataRaw"`
	DeployType common.DeployType   `json:"deployType"`
	// Digest is the SHA-256 of every other persisted field (metadata and DataRaw).
	// Artifacts written by older versions without the digest are still accepted.
	Digest    string              `json:"digest"`
	Encrypted bool                `json:"encrypted"`
	Release   PlanArtifactRelease `json:"release"`

	Timestamp time.Time `json:"timestamp"`
}

type PlanArtifactData struct {
	Options                  common.ReleaseInstallRuntimeOptions `json:"options"`
	Changes                  []*plan.ResourceChange              `json:"changes"`
	Plan                     *plan.Plan                          `json:"plan"`
	Release                  *release.VersionedRelease           `json:"release"`
	InstallableResourceInfos []*plan.InstallableResourceInfo     `json:"installableResourceInfos"`
	ReleaseInfos             []*plan.ReleaseInfo                 `json:"releaseInfos"`
}

type PlanArtifactRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Revision  int    `json:"revision"`
}

type planArtifactDigestInput struct {
	APIVersion string              `json:"apiVersion"`
	DataRaw    string              `json:"dataRaw"`
	DeployType common.DeployType   `json:"deployType"`
	Encrypted  bool                `json:"encrypted"`
	Release    PlanArtifactRelease `json:"release"`
	Timestamp  time.Time           `json:"timestamp"`
}

func planArtifactDigest(artifact *PlanArtifact) string {
	input := planArtifactDigestInput{
		APIVersion: artifact.APIVersion,
		DataRaw:    artifact.DataRaw,
		DeployType: artifact.DeployType,
		Encrypted:  artifact.Encrypted,
		Release:    artifact.Release,
		Timestamp:  artifact.Timestamp,
	}

	sum := sha256.Sum256(lo.Must(json.Marshal(input)))

	return hex.EncodeToString(sum[:])
}

func planArtifactLockPath(targetPath string) string {
	return targetPath + ".lock"
}

func planArtifactCandidateGlob(targetPath string) string {
	return filepath.Join(filepath.Dir(targetPath), "."+filepath.Base(targetPath)+".candidate-*")
}

// lockPlanArtifact serializes artifact publishing for targetPath. The lock is
// mandatory for writers and best-effort for readers: a read-only directory may
// reject the lock file, in which case stale candidate cleanup is skipped.
func lockPlanArtifact(ctx context.Context, targetPath string, required bool) (func(), error) {
	fileLock := flock.New(planArtifactLockPath(targetPath))

	if err := fileLock.Lock(); err != nil {
		if required {
			return nil, fmt.Errorf("acquire plan artifact lock for %q: %w", targetPath, err)
		}

		log.Default.Debug(ctx, "Cannot acquire plan artifact lock for %q: %w", targetPath, err)

		return func() {}, nil
	}

	return func() {
		if err := fileLock.Unlock(); err != nil {
			log.Default.Debug(ctx, "Release plan artifact lock for %q: %w", targetPath, err)
		}
	}, nil
}

func removeUnpublishedPlanArtifactCandidates(ctx context.Context, targetPath string) {
	candidatePaths, err := filepath.Glob(planArtifactCandidateGlob(targetPath))
	if err != nil {
		log.Default.Debug(ctx, "Cannot list unpublished plan artifact candidates for %q: %w", targetPath, err)

		return
	}

	for _, candidatePath := range candidatePaths {
		info, err := os.Lstat(candidatePath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				log.Default.Debug(ctx, "Cannot stat unpublished plan artifact candidate %q: %w", candidatePath, err)
			}

			continue
		}

		if !info.Mode().IsRegular() {
			continue
		}

		if err := os.Remove(candidatePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Default.Debug(ctx, "Cannot remove unpublished plan artifact candidate %q: %w", candidatePath, err)
		}
	}
}

func ReadPlanArtifact(ctx context.Context, path, secretKey, secretWorkDir string) (*PlanArtifact, error) {
	unlock, err := lockPlanArtifact(ctx, path, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

	removeUnpublishedPlanArtifactCandidates(ctx, path)

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plan artifact file: %w", err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	// Reading the whole stream forces gzip footer verification (CRC32 and size),
	// so truncated files fail, and the multistream header check rejects bytes
	// trailing the only allowed gzip member.
	decompressed, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("decompress plan artifact: %w", err)
	}

	var artifact PlanArtifact

	decoder := json.NewDecoder(bytes.NewReader(decompressed))

	if err := decoder.Decode(&artifact); err != nil {
		return nil, fmt.Errorf("decode plan artifact json: %w", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode plan artifact json: unexpected trailing content")
		}

		return nil, fmt.Errorf("decode plan artifact json: %w", err)
	}

	if artifact.APIVersion != PlanArtifactSchemeVersion {
		return nil, fmt.Errorf("plan artifact %s is not supported by the current version", artifact.APIVersion)
	}

	if artifact.DataRaw == "" {
		return nil, fmt.Errorf("artifact data is empty")
	}

	if artifact.Digest != "" {
		expectedDigest := planArtifactDigest(&artifact)
		if subtle.ConstantTimeCompare([]byte(artifact.Digest), []byte(expectedDigest)) != 1 {
			return nil, fmt.Errorf("plan artifact integrity check failed: metadata or data digest mismatch")
		}
	}

	var dataJSON []byte

	if artifact.Encrypted {
		if secretKey == "" {
			return nil, fmt.Errorf("artifact is encrypted but no secret key provided")
		}

		lo.Must0(os.Setenv("WERF_SECRET_KEY", secretKey))

		encoder, err := secrets_manager.Manager.GetYamlEncoder(ctx, secretWorkDir, false)
		if err != nil {
			return nil, fmt.Errorf("get yaml encoder: %w", err)
		}

		dataJSON, err = encoder.Decrypt([]byte(artifact.DataRaw))
		if err != nil {
			return nil, fmt.Errorf("decrypt artifact data: %w", err)
		}
	} else {
		dataJSON = []byte(artifact.DataRaw)
	}

	var data PlanArtifactData

	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return nil, fmt.Errorf("decode artifact data json: %w", err)
	}

	artifact.Data = &data

	return &artifact, nil
}

func ValidatePlanArtifact(artifact *PlanArtifact, lifetime time.Duration) error {
	if artifact == nil {
		return errors.New("plan shouldn't be empty")
	}

	if artifact.Timestamp.Add(lifetime).Before(time.Now().UTC()) {
		return fmt.Errorf("plan artifact expired: was valid for %s until %s",
			lifetime, artifact.Timestamp.Add(lifetime).Format(time.RFC3339))
	}

	if artifact.Release.Namespace == "" {
		return errors.New("release namespace is not set")
	}

	if artifact.Release.Name == "" {
		return errors.New("release name is not set")
	}

	if artifact.Data.Plan == nil {
		return errors.New("plan is not set")
	}

	if len(artifact.Data.InstallableResourceInfos) == 0 {
		return errors.New("no installable resource information objects found")
	}

	if len(artifact.Data.ReleaseInfos) == 0 {
		return errors.New("no release information objects found")
	}

	return nil
}

func WritePlanArtifact(ctx context.Context, artifact *PlanArtifact, path, secretKey, secretWorkDir string) error {
	dataJSON, err := json.Marshal(artifact.Data)
	if err != nil {
		return fmt.Errorf("marshal artifact data to json: %w", err)
	}

	if secretKey != "" {
		lo.Must0(os.Setenv("WERF_SECRET_KEY", secretKey))

		encoder, err := secrets_manager.Manager.GetYamlEncoder(ctx, secretWorkDir, false)
		if err != nil {
			return fmt.Errorf("get yaml encoder: %w", err)
		}

		encryptedData, err := encoder.Encrypt(dataJSON)
		if err != nil {
			return fmt.Errorf("encrypt artifact data: %w", err)
		}

		artifact.DataRaw = string(encryptedData)
		artifact.Encrypted = true
	} else {
		artifact.DataRaw = string(dataJSON)
		artifact.Encrypted = false
	}

	artifact.Digest = planArtifactDigest(artifact)

	unlock, err := lockPlanArtifact(ctx, path, true)
	if err != nil {
		return err
	}
	defer unlock()

	removeUnpublishedPlanArtifactCandidates(ctx, path)

	candidatePath, err := writePlanArtifactCandidate(ctx, artifact, path)
	if err != nil {
		return err
	}

	if err := os.Rename(candidatePath, path); err != nil {
		if removeErr := os.Remove(candidatePath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			log.Default.Debug(ctx, "Cannot remove unpublished plan artifact candidate %q: %w", candidatePath, removeErr)
		}

		return fmt.Errorf("replace plan artifact file %q: %w", path, err)
	}

	if err := syncPlanArtifactDir(path); err != nil {
		log.Default.Warn(ctx, "Cannot synchronize directory of plan artifact %q: %w", path, err)
	}

	return nil
}

// writePlanArtifactCandidate fully encodes the artifact into an unpublished
// candidate file next to the target and synchronizes it. The target is never
// touched, so the previous artifact stays readable until the caller renames.
func writePlanArtifactCandidate(ctx context.Context, artifact *PlanArtifact, targetPath string) (string, error) {
	candidate, err := os.CreateTemp(filepath.Dir(targetPath), "."+filepath.Base(targetPath)+".candidate-*")
	if err != nil {
		return "", fmt.Errorf("create plan artifact candidate file for %q: %w", targetPath, err)
	}

	candidatePath := candidate.Name()

	removeCandidate := func() {
		if err := os.Remove(candidatePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Default.Debug(ctx, "Cannot remove unpublished plan artifact candidate %q: %w", candidatePath, err)
		}
	}

	fail := func(err error) (string, error) {
		if closeErr := candidate.Close(); closeErr != nil && !errors.Is(closeErr, fs.ErrClosed) {
			log.Default.Debug(ctx, "Cannot close plan artifact candidate %q: %w", candidatePath, closeErr)
		}

		removeCandidate()

		return "", err
	}

	gzipWriter := gzip.NewWriter(candidate)

	jsonEncoder := json.NewEncoder(gzipWriter)
	jsonEncoder.SetIndent("", "  ")

	if err := jsonEncoder.Encode(artifact); err != nil {
		if closeErr := gzipWriter.Close(); closeErr != nil {
			log.Default.Debug(ctx, "Cannot close plan artifact gzip writer: %w", closeErr)
		}

		return fail(fmt.Errorf("marshal plan artifact to json: %w", err))
	}

	if err := gzipWriter.Close(); err != nil {
		return fail(fmt.Errorf("close plan artifact gzip writer: %w", err))
	}

	if err := candidate.Sync(); err != nil {
		return fail(fmt.Errorf("sync plan artifact candidate %q: %w", candidatePath, err))
	}

	if err := candidate.Close(); err != nil {
		removeCandidate()

		return "", fmt.Errorf("close plan artifact candidate %q: %w", candidatePath, err)
	}

	if err := os.Chmod(candidatePath, 0o644); err != nil {
		removeCandidate()

		return "", fmt.Errorf("chmod plan artifact candidate %q: %w", candidatePath, err)
	}

	return candidatePath, nil
}

func syncPlanArtifactDir(targetPath string) error {
	dir, err := os.Open(filepath.Dir(targetPath))
	if err != nil {
		return fmt.Errorf("open directory: %w", err)
	}
	defer dir.Close()

	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}

	return nil
}
