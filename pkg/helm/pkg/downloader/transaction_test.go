/*
Copyright The Helm Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package downloader

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/werf/nelm/v2/pkg/helm/intern/third_party/dep/fs"
	"github.com/werf/nelm/v2/pkg/helm/pkg/helmpath"
)

func newTestManager(t *testing.T, chartPath string) *Manager {
	t.Helper()
	return &Manager{
		Out:              io.Discard,
		ChartPath:        chartPath,
		RepositoryConfig: filepath.Join(t.TempDir(), "repositories.yaml"),
		RepositoryCache:  t.TempDir(),
	}
}

// tempRepoCache seeds a temporary repository cache with the testdata indices,
// so that per-chart dependency lock files never touch the package testdata.
func tempRepoCache(t *testing.T) string {
	t.Helper()
	cache := filepath.Join(t.TempDir(), "repository")
	require.NoError(t, fs.CopyDir("testdata/repository", cache))
	return cache
}

func TestDependencyTxnCreateAndCleanup(t *testing.T) {
	chartPath := t.TempDir()
	m := newTestManager(t, chartPath)

	var workspaceRoot string
	err := m.withDependencyTxn(context.Background(), func(_ context.Context, txn *dependencyTxn) error {
		workspaceRoot = txn.root

		assert.Regexp(t, `^tmpcharts-\d+-\d+-[0-9a-f]+$`, filepath.Base(txn.root))
		require.DirExists(t, txn.candidateChartsDir())

		journal, err := readDepTxnJournal(txn.root)
		require.NoError(t, err)
		require.NotNil(t, journal)
		assert.Equal(t, 1, journal.Version)
		assert.Equal(t, txnPhaseStaging, journal.Phase)
		assert.Equal(t, os.Getpid(), journal.PID)
		assert.False(t, journal.StartedAt.IsZero())
		return nil
	})
	require.NoError(t, err)

	_, err = os.Stat(workspaceRoot)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestClassifyStaleWorkspace(t *testing.T) {
	chartPath := t.TempDir()
	m := newTestManager(t, chartPath)

	current, err := (&dependencyTxn{m: m, chartPath: chartPath}).makeWorkspaceDir()
	require.NoError(t, err)
	currentTxn := &dependencyTxn{
		m:         m,
		chartPath: chartPath,
		root:      current,
		journal:   &depTxnJournal{Version: 1, Phase: txnPhaseStaging, PID: os.Getpid(), StartedAt: time.Now()},
	}
	require.NoError(t, currentTxn.writeJournal())

	kind, journal := classifyStaleWorkspace(current)
	assert.Equal(t, staleWorkspaceOurs, kind)
	require.NotNil(t, journal)
	assert.Equal(t, 1, journal.Version)

	currentWithoutJournal, err := (&dependencyTxn{m: m, chartPath: chartPath}).makeWorkspaceDir()
	require.NoError(t, err)
	kind, journal = classifyStaleWorkspace(currentWithoutJournal)
	assert.Equal(t, staleWorkspaceOurs, kind)
	assert.Nil(t, journal)

	corruptJournal := filepath.Join(chartPath, "tmpcharts-1-2-abcd")
	require.NoError(t, os.MkdirAll(corruptJournal, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(corruptJournal, depTxnJournalFile), []byte("{not-json"), 0o644))
	kind, journal = classifyStaleWorkspace(corruptJournal)
	assert.Equal(t, staleWorkspaceOurs, kind)
	assert.Nil(t, journal)

	legacy := filepath.Join(chartPath, "tmpcharts-12345")
	require.NoError(t, os.MkdirAll(legacy, 0o755))
	kind, journal = classifyStaleWorkspace(legacy)
	assert.Equal(t, staleWorkspaceLegacy, kind)
	assert.Nil(t, journal)

	foreign := filepath.Join(chartPath, "tmpcharts-backup")
	require.NoError(t, os.MkdirAll(foreign, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(foreign, depTxnJournalFile), []byte("garbage"), 0o644))
	kind, journal = classifyStaleWorkspace(foreign)
	assert.Equal(t, staleWorkspaceForeign, kind)
	assert.Nil(t, journal)
}

func TestRecoverStaleWorkspaces(t *testing.T) {
	chartPath := t.TempDir()
	m := newTestManager(t, chartPath)
	out := &bytes.Buffer{}
	m.Out = out

	ours, err := (&dependencyTxn{m: m, chartPath: chartPath}).makeWorkspaceDir()
	require.NoError(t, err)
	txn := &dependencyTxn{m: m, chartPath: chartPath, root: ours}
	txn.journal = &depTxnJournal{Version: 1, Phase: txnPhasePrepared, LockName: "Chart.lock", PID: os.Getpid(), StartedAt: time.Now()}
	require.NoError(t, txn.writeJournal())

	legacy := filepath.Join(chartPath, "tmpcharts-12345")
	require.NoError(t, os.MkdirAll(legacy, 0o755))

	foreign := filepath.Join(chartPath, "tmpcharts-backup")
	require.NoError(t, os.MkdirAll(foreign, 0o755))

	userDir := filepath.Join(chartPath, "tmpcharts")
	require.NoError(t, os.MkdirAll(userDir, 0o755))

	nonDir := filepath.Join(chartPath, "tmpcharts-67890")
	require.NoError(t, os.WriteFile(nonDir, []byte("data"), 0o644))

	require.NoError(t, m.recoverStaleWorkspaces(chartPath, context.Background()))

	_, err = os.Stat(legacy)
	assert.ErrorIs(t, err, os.ErrNotExist, "legacy workspace must be removed")
	_, err = os.Stat(ours)
	assert.ErrorIs(t, err, os.ErrNotExist, "prepared workspace without published generation must be discarded")

	assert.DirExists(t, foreign)
	assert.DirExists(t, userDir)
	assert.FileExists(t, nonDir)
	assert.Contains(t, out.String(), "not a directory, skipping")
}

func TestDependencyTxnLockMutualExclusion(t *testing.T) {
	chartPath := t.TempDir()
	m := newTestManager(t, chartPath)

	absChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)
	lockPath, err := m.dependencyLockPath(absChartPath)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(lockPath), 0o755))

	holder := flock.New(lockPath)
	require.NoError(t, holder.Lock())
	defer func() { require.NoError(t, holder.Unlock()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err = m.withDependencyTxn(ctx, func(context.Context, *dependencyTxn) error {
		t.Fatal("transaction body must not run while the lock is held")
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acquire dependency lock")
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath), "no workspace must be created without the lock")

	require.NoError(t, holder.Unlock())
	ran := false
	require.NoError(t, m.withDependencyTxn(context.Background(), func(context.Context, *dependencyTxn) error {
		ran = true
		return nil
	}))
	assert.True(t, ran)
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestDependencyLockPath(t *testing.T) {
	cacheDir := t.TempDir()
	chartPath := filepath.Join(t.TempDir(), "mychart")
	m := &Manager{RepositoryCache: cacheDir}

	absChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)
	sum, err := key(absChartPath)
	require.NoError(t, err)

	expected := filepath.Join(cacheDir, depTxnLocksDir, sum+".lock")
	lockPath, err := m.dependencyLockPath(absChartPath)
	require.NoError(t, err)
	assert.Equal(t, expected, lockPath)

	lockPathAgain, err := m.dependencyLockPath(absChartPath)
	require.NoError(t, err)
	assert.Equal(t, lockPath, lockPathAgain)

	otherPath, err := m.dependencyLockPath(absChartPath+"-other")
	require.NoError(t, err)
	assert.NotEqual(t, lockPath, otherPath)

	mFallback := &Manager{}
	fallbackPath, err := mFallback.dependencyLockPath(absChartPath)
	require.NoError(t, err)
	expectedFallback, err := func() (string, error) {
		fallbackSum, err := key(absChartPath)
		if err != nil {
			return "", err
		}
		return filepath.Join(helmpath.CachePath("repository"), depTxnLocksDir, fallbackSum+".lock"), nil
	}()
	require.NoError(t, err)
	assert.Equal(t, expectedFallback, fallbackPath)
}

func TestDepTxnJournalCorrupt(t *testing.T) {
	chartPath := t.TempDir()

	journal, err := readDepTxnJournal(chartPath)
	require.NoError(t, err)
	assert.Nil(t, journal)

	require.NoError(t, os.WriteFile(filepath.Join(chartPath, depTxnJournalFile), []byte("not-json"), 0o644))
	_, err = readDepTxnJournal(chartPath)
	assert.Error(t, err)
}

func listTmpWorkspaceEntries(t *testing.T, chartPath string) []string {
	t.Helper()
	entries, err := os.ReadDir(chartPath)
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), depTxnPrefix) {
			names = append(names, entry.Name())
		}
	}
	return names
}
