package action

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/werf/nelm/v2/pkg/common"
)

const (
	testNamespace    = "test-namespace"
	testPayloadValue = "super-secret-plan-payload"
	testSecretKey    = "0123456789abcdef0123456789abcdef"
	testWrongKey     = "fedcba9876543210fedcba9876543210"
)

func TestPlanArtifact_RemovesUnpublishedCandidatesOnWriteAndRead(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "candidate-release", ""), path, "", ""))

	staleCandidatePath := filepath.Join(filepath.Dir(path), ".plan.json.candidate-stale")
	require.NoError(t, os.WriteFile(staleCandidatePath, []byte("unpublished"), 0o644))

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "candidate-release", ""), path, "", ""))

	_, err := os.Lstat(staleCandidatePath)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, os.WriteFile(staleCandidatePath, []byte("unpublished"), 0o644))

	_, err = ReadPlanArtifact(ctx, path, "", "")
	require.NoError(t, err)

	_, err = os.Lstat(staleCandidatePath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadPlanArtifact_AcceptsLegacyArtifactWithoutDigest(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	writeLegacyArtifact(t, path, PlanArtifactSchemeVersion, false, `{"options":{}}`)

	artifact, err := ReadPlanArtifact(ctx, path, "", "")
	require.NoError(t, err)
	assert.Empty(t, artifact.Digest)
	assert.Equal(t, "legacy-release", artifact.Release.Name)
}

func TestReadPlanArtifact_RejectsOldTailFromShorterRewrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "plan.json")

	bigArtifact := testPlanArtifact(t, "big-release", strings.Repeat("x", 256*1024))
	require.NoError(t, WritePlanArtifact(ctx, bigArtifact, targetPath, "", ""))

	bigRaw, err := os.ReadFile(targetPath)
	require.NoError(t, err)

	smallArtifact := testPlanArtifact(t, "small-release", "short")
	require.NoError(t, WritePlanArtifact(ctx, smallArtifact, filepath.Join(dir, "small.json"), "", ""))

	smallRaw, err := os.ReadFile(filepath.Join(dir, "small.json"))
	require.NoError(t, err)
	require.Less(t, len(smallRaw), len(bigRaw))

	// Simulate the legacy writer that replaced contents without O_TRUNC:
	// the shorter new stream followed by the previous file's tail.
	mixed := append(append([]byte{}, smallRaw...), bigRaw[len(smallRaw):]...)
	overwriteFile(t, targetPath, mixed)

	_, err = ReadPlanArtifact(ctx, targetPath, "", "")
	require.Error(t, err)
}

func TestReadPlanArtifact_RejectsTamperedDataRaw(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "tampered-release", ""), path, "", ""))

	mutatePersistedArtifact(t, path, func(doc map[string]any) {
		doc["dataRaw"] = `{"options":{}}`
	})

	_, err := ReadPlanArtifact(ctx, path, "", "")
	require.ErrorContains(t, err, "integrity check failed")
}

func TestReadPlanArtifact_RejectsTamperedMetadata(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "tampered-release", ""), path, "", ""))

	mutatePersistedArtifact(t, path, func(doc map[string]any) {
		doc["release"].(map[string]any)["name"] = "hijacked-release"
	})

	_, err := ReadPlanArtifact(ctx, path, "", "")
	require.ErrorContains(t, err, "integrity check failed")
}

func TestReadPlanArtifact_RejectsTrailingGarbage(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "trailing-release", ""), path, "", ""))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	overwriteFile(t, path, append(raw, []byte("trailing garbage")...))

	_, err = ReadPlanArtifact(ctx, path, "", "")
	require.Error(t, err)
}

func TestReadPlanArtifact_RejectsTrailingJSON(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "trailing-json-release", ""), path, "", ""))

	content := gunzipArtifactFile(t, path)
	content = append(content, []byte(` {"unexpected":true}`)...)
	writeGzippedBytes(t, path, content)

	_, err := ReadPlanArtifact(ctx, path, "", "")
	require.ErrorContains(t, err, "unexpected trailing content")
}

func TestReadPlanArtifact_RejectsTruncatedFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "truncated-release", ""), path, "", ""))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	overwriteFile(t, path, raw[:len(raw)/2])

	_, err = ReadPlanArtifact(ctx, path, "", "")
	require.ErrorContains(t, err, "decompress plan artifact")
}

func TestReadPlanArtifact_RejectsUnsupportedScheme(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	writeLegacyArtifact(t, path, "v1", false, `{"options":{}}`)

	_, err := ReadPlanArtifact(ctx, path, "", "")
	require.ErrorContains(t, err, "not supported by the current version")
}

func TestWritePlanArtifact_ConcurrentWritersPublishSingleCompleteGeneration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "release-0", ""), path, "", ""))

	const writerCount = 24

	var writers sync.WaitGroup

	writerErrors := make(chan error, writerCount)

	for writer := 0; writer < writerCount; writer++ {
		writers.Add(1)

		go func(writer int) {
			defer writers.Done()

			artifact := testPlanArtifact(
				t,
				fmt.Sprintf("release-%d", writer),
				fmt.Sprintf("%d-%s", writer, strings.Repeat("x", 16*1024)),
			)

			writerErrors <- WritePlanArtifact(ctx, artifact, path, "", "")
		}(writer)
	}

	const readerCount = 4

	var readers sync.WaitGroup

	stopReaders := make(chan struct{})
	readerErrors := make(chan error, writerCount*readerCount)

	for reader := 0; reader < readerCount; reader++ {
		readers.Add(1)

		go func() {
			defer readers.Done()

			for {
				select {
				case <-stopReaders:
					return
				default:
				}

				artifact, err := ReadPlanArtifact(ctx, path, "", "")
				if err != nil {
					readerErrors <- err

					return
				}

				if artifact == nil || artifact.Release.Name == "" {
					readerErrors <- fmt.Errorf("read incomplete plan artifact generation")
				}
			}
		}()
	}

	writers.Wait()
	close(stopReaders)
	readers.Wait()
	close(writerErrors)
	close(readerErrors)

	for err := range writerErrors {
		require.NoError(t, err)
	}

	for err := range readerErrors {
		require.NoError(t, err)
	}

	artifact, err := ReadPlanArtifact(ctx, path, "", "")
	require.NoError(t, err)
	assert.Regexp(t, "^release-\\d+$", artifact.Release.Name)
	require.NotNil(t, artifact.Data)
	assert.Greater(t, len(artifact.Data.Options.ExtraAnnotations["payload"]), 16*1024)

	expectedDataRaw, err := json.Marshal(artifact.Data)
	require.NoError(t, err)
	assert.Equal(t, string(expectedDataRaw), artifact.DataRaw)

	candidates, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".plan.json.candidate-*"))
	require.NoError(t, err)
	assert.Empty(t, candidates)
}

func TestWritePlanArtifact_FailureKeepsPreviousArtifact(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	require.NoError(t, WritePlanArtifact(ctx, testPlanArtifact(t, "previous-release", ""), path, "", ""))

	missingDirPath := filepath.Join(t.TempDir(), "missing-dir", "plan.json")

	err := WritePlanArtifact(ctx, testPlanArtifact(t, "failed-release", ""), missingDirPath, "", "")
	require.Error(t, err)

	artifact, err := ReadPlanArtifact(ctx, path, "", "")
	require.NoError(t, err)
	assert.Equal(t, "previous-release", artifact.Release.Name)

	candidates, err := filepath.Glob(filepath.Join(filepath.Dir(missingDirPath), ".plan.json.candidate-*"))
	require.NoError(t, err)
	assert.Empty(t, candidates)
}

func TestWritePlanArtifact_ShorterRewriteLeavesNoOldTail(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "plan.json")
	referencePath := filepath.Join(dir, "reference.json")

	bigArtifact := testPlanArtifact(t, "big-release", strings.Repeat("x", 256*1024))
	require.NoError(t, WritePlanArtifact(ctx, bigArtifact, targetPath, "", ""))

	smallArtifact := testPlanArtifact(t, "small-release", "short")
	require.NoError(t, WritePlanArtifact(ctx, smallArtifact, referencePath, "", ""))
	require.NoError(t, WritePlanArtifact(ctx, smallArtifact, targetPath, "", ""))

	targetRaw, err := os.ReadFile(targetPath)
	require.NoError(t, err)

	referenceRaw, err := os.ReadFile(referencePath)
	require.NoError(t, err)

	assert.Equal(t, referenceRaw, targetRaw)

	readArtifact, err := ReadPlanArtifact(ctx, targetPath, "", "")
	require.NoError(t, err)
	assert.Equal(t, "small-release", readArtifact.Release.Name)
	assert.Equal(t, "short", readArtifact.Data.Options.ExtraAnnotations["payload"])
}

func TestWriteReadPlanArtifact_EncryptedRoundTripAndWrongKey(t *testing.T) {
	ctx := context.Background()
	secretWorkDir := t.TempDir()
	path := filepath.Join(t.TempDir(), "plan.json")

	t.Setenv("WERF_SECRET_KEY", testSecretKey)

	artifact := testPlanArtifact(t, "encrypted-release", testPayloadValue)

	require.NoError(t, WritePlanArtifact(ctx, artifact, path, testSecretKey, secretWorkDir))

	content := gunzipArtifactFile(t, path)

	var persisted map[string]any
	require.NoError(t, json.Unmarshal(content, &persisted))
	assert.Equal(t, true, persisted["encrypted"])
	assert.NotContains(t, persisted["dataRaw"], testPayloadValue)

	readArtifact, err := ReadPlanArtifact(ctx, path, testSecretKey, secretWorkDir)
	require.NoError(t, err)
	assert.Equal(t, testPayloadValue, readArtifact.Data.Options.ExtraAnnotations["payload"])

	_, err = ReadPlanArtifact(ctx, path, testWrongKey, secretWorkDir)
	require.ErrorContains(t, err, "decrypt artifact data")

	_, err = ReadPlanArtifact(ctx, path, "", secretWorkDir)
	require.ErrorContains(t, err, "no secret key provided")
}

func TestWriteReadPlanArtifact_PlaintextRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plan.json")

	artifact := testPlanArtifact(t, "plain-release", testPayloadValue)

	require.NoError(t, WritePlanArtifact(ctx, artifact, path, "", t.TempDir()))

	readArtifact, err := ReadPlanArtifact(ctx, path, "", "")
	require.NoError(t, err)

	assert.Equal(t, PlanArtifactSchemeVersion, readArtifact.APIVersion)
	assert.False(t, readArtifact.Encrypted)
	assert.Len(t, readArtifact.Digest, 64)
	assert.Equal(t, "plain-release", readArtifact.Release.Name)
	require.NotNil(t, readArtifact.Data)
	assert.Equal(t, testPayloadValue, readArtifact.Data.Options.ExtraAnnotations["payload"])

	expectedDataRaw, err := json.Marshal(readArtifact.Data)
	require.NoError(t, err)
	assert.Equal(t, string(expectedDataRaw), readArtifact.DataRaw)
	assert.Equal(t, planArtifactDigest(readArtifact), readArtifact.Digest)
}

func mutatePersistedArtifact(t *testing.T, path string, mutate func(doc map[string]any)) {
	t.Helper()

	content := gunzipArtifactFile(t, path)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(content, &doc))

	mutate(doc)

	mutated, err := json.Marshal(doc)
	require.NoError(t, err)

	writeGzippedBytes(t, path, mutated)
}

func writeLegacyArtifact(t *testing.T, path, apiVersion string, encrypted bool, dataRaw string) {
	t.Helper()

	doc := map[string]any{
		"apiVersion": apiVersion,
		"dataRaw":    dataRaw,
		"deployType": string(common.DeployTypeInstall),
		"encrypted":  encrypted,
		"release": map[string]any{
			"name":      "legacy-release",
			"namespace": testNamespace,
			"revision":  1,
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}

	content, err := json.Marshal(doc)
	require.NoError(t, err)

	writeGzippedBytes(t, path, content)
}

func gunzipArtifactFile(t *testing.T, path string) []byte {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	gzipReader, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)

	content, err := io.ReadAll(gzipReader)
	require.NoError(t, err)
	require.NoError(t, gzipReader.Close())

	return content
}

func testPlanArtifact(t *testing.T, releaseName, annotationPayload string) *PlanArtifact {
	t.Helper()

	data := &PlanArtifactData{
		Options: common.ReleaseInstallRuntimeOptions{},
	}

	if annotationPayload != "" {
		data.Options.ExtraAnnotations = map[string]string{"payload": annotationPayload}
	}

	return &PlanArtifact{
		APIVersion: PlanArtifactSchemeVersion,
		Data:       data,
		DeployType: common.DeployTypeInstall,
		Release: PlanArtifactRelease{
			Name:      releaseName,
			Namespace: testNamespace,
			Revision:  1,
		},
		Timestamp: time.Now().UTC(),
	}
}

func writeGzippedBytes(t *testing.T, path string, content []byte) {
	t.Helper()

	file, err := os.Create(path)
	require.NoError(t, err)

	gzipWriter := gzip.NewWriter(file)
	_, err = gzipWriter.Write(content)
	require.NoError(t, err)
	require.NoError(t, gzipWriter.Close())
	require.NoError(t, file.Close())
}

func overwriteFile(t *testing.T, path string, content []byte) {
	t.Helper()

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o644)
	require.NoError(t, err)

	_, err = file.Write(content)
	require.NoError(t, err)
	require.NoError(t, file.Close())
}
