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
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/werf/nelm/v2/pkg/helm/intern/resolver"
	"github.com/werf/nelm/v2/pkg/helm/intern/third_party/dep/fs"
	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/loader"
	chartutil "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/util"
)

var (
	oldGenerationDeps = []*chart.Dependency{{Name: "signtest", Version: "0.1.0", Repository: "file://./signtest"}}
	newGenerationDeps = []*chart.Dependency{{Name: "local-subchart", Version: "0.1.0", Repository: "https://example.com/charts"}}
)

func testArchivePath(dep *chart.Dependency) string {
	return filepath.Join("testdata", dep.Name+"-"+dep.Version+".tgz")
}

func writeTestChartMetadata(t *testing.T, chartDir string, deps []*chart.Dependency) {
	t.Helper()
	md := &chart.Metadata{APIVersion: chart.APIVersionV2, Name: "parent", Version: "1.0.0", Dependencies: deps}
	data, err := yaml.Marshal(md)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), data, 0o644))
}

func writeTestLockFile(t *testing.T, chartDir, lockName string, deps []*chart.Dependency) *chart.Lock {
	t.Helper()
	digest, err := resolver.HashReq(deps, deps)
	require.NoError(t, err)
	lock := &chart.Lock{Digest: digest, Dependencies: deps}
	data, err := yaml.Marshal(lock)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, lockName), data, 0o644))
	return lock
}

func writeGeneration(t *testing.T, chartDir, lockName string, deps []*chart.Dependency) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts"), 0o755))
	writeTestChartMetadata(t, chartDir, deps)
	writeTestLockFile(t, chartDir, lockName, deps)
	for _, dep := range deps {
		if dep.Repository == "" {
			continue
		}
		data, err := os.ReadFile(testArchivePath(dep))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(chartDir, "charts", dep.Name+"-"+dep.Version+".tgz"), data, 0o644))
	}
}

func assertGeneration(t *testing.T, chartDir, lockName string, deps []*chart.Dependency) {
	t.Helper()
	c, err := loader.LoadDir(context.Background(), chartDir)
	require.NoError(t, err)
	require.NotNil(t, c.Lock)
	assert.Equal(t, deps[0].Name+"-"+deps[0].Version+".tgz", filepath.Base(mustFirstArchive(t, chartDir)))
	require.NoError(t, verifyGeneration(context.Background(), filepath.Join(chartDir, "charts"), filepath.Join(chartDir, "charts"), c.Metadata.Dependencies, c.Lock))

	lockData, err := os.ReadFile(filepath.Join(chartDir, lockName))
	require.NoError(t, err)
	parsedLock := new(chart.Lock)
	require.NoError(t, yaml.Unmarshal(lockData, parsedLock))
	assert.Equal(t, c.Lock.Digest, parsedLock.Digest)
}

func mustFirstArchive(t *testing.T, chartDir string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(chartDir, "charts"))
	require.NoError(t, err)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tgz" {
			return filepath.Join(chartDir, "charts", entry.Name())
		}
	}
	t.Fatal("no archive found")
	return ""
}

func seedRecoverWorkspace(t *testing.T, m *Manager, chartPath string, phase txnPhase, publishLock bool, corruptJournal bool, layout func(txn *dependencyTxn)) string {
	t.Helper()
	txn := &dependencyTxn{m: m, chartPath: chartPath}
	root, err := txn.makeWorkspaceDir()
	require.NoError(t, err)
	txn.root = root
	txn.journal = &depTxnJournal{
		Version:     1,
		Phase:       phase,
		PublishLock: publishLock,
		LockName:    "Chart.lock",
		PID:         os.Getpid(),
	}
	layout(txn)
	if corruptJournal {
		require.NoError(t, os.WriteFile(filepath.Join(root, depTxnJournalFile), []byte("{corrupt"), 0o644))
	} else {
		require.NoError(t, txn.writeJournal())
	}
	return root
}

func putArchive(t *testing.T, dir string, dep *chart.Dependency) {
	t.Helper()
	data, err := os.ReadFile(testArchivePath(dep))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, dep.Name+"-"+dep.Version+".tgz"), data, 0o644))
}

func mustBuildLock(t *testing.T, deps []*chart.Dependency) *chart.Lock {
	t.Helper()
	digest, err := resolver.HashReq(deps, deps)
	require.NoError(t, err)
	return &chart.Lock{Digest: digest, Dependencies: deps}
}

func TestRecoverWorkspaceCrashTable(t *testing.T) {
	t.Run("1 prepared: current generation stays", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		root := seedRecoverWorkspace(t, m, chartDir, txnPhasePrepared, true, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.candidateChartsDir(), 0o755))
			putArchive(t, txn.candidateChartsDir(), newGenerationDeps[0])
			require.NoError(t, txn.stageCandidateLock(mustBuildLock(t, newGenerationDeps)))
		})

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assertGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("2 charts backed up only: charts restored, lock untouched", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeTestChartMetadata(t, chartDir, oldGenerationDeps)
		writeTestLockFile(t, chartDir, "Chart.lock", oldGenerationDeps)
		root := seedRecoverWorkspace(t, m, chartDir, txnPhaseBackingUp, true, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
			putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
			require.NoError(t, os.MkdirAll(txn.candidateChartsDir(), 0o755))
			putArchive(t, txn.candidateChartsDir(), newGenerationDeps[0])
			require.NoError(t, txn.stageCandidateLock(mustBuildLock(t, newGenerationDeps)))
		})

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assertGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("3 charts and lock backed up: both restored", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		root := seedRecoverWorkspace(t, m, chartDir, txnPhaseBackingUp, true, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
			putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
			oldLock := mustBuildLock(t, oldGenerationDeps)
			oldData, err := yaml.Marshal(oldLock)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(txn.backupLockPath(), oldData, 0o644))
			require.NoError(t, os.MkdirAll(txn.candidateChartsDir(), 0o755))
			putArchive(t, txn.candidateChartsDir(), newGenerationDeps[0])
			require.NoError(t, txn.stageCandidateLock(mustBuildLock(t, newGenerationDeps)))
		})
		writeTestChartMetadata(t, chartDir, oldGenerationDeps)

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assertGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("4 only charts published: rollback to backup", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeTestChartMetadata(t, chartDir, oldGenerationDeps)
		require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts"), 0o755))
		putArchive(t, filepath.Join(chartDir, "charts"), newGenerationDeps[0])
		root := seedRecoverWorkspace(t, m, chartDir, txnPhasePublishing, true, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
			putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
			oldData, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(txn.backupLockPath(), oldData, 0o644))
			require.NoError(t, txn.stageCandidateLock(mustBuildLock(t, newGenerationDeps)))
		})

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assertGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("5 committed and verified: new generation accepted", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeGeneration(t, chartDir, "Chart.lock", newGenerationDeps)
		root := seedRecoverWorkspace(t, m, chartDir, txnPhaseCommitted, true, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
			putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
			oldData, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(txn.backupLockPath(), oldData, 0o644))
		})

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assertGeneration(t, chartDir, "Chart.lock", newGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("6 committed but broken: rollback to previous generation", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeTestChartMetadata(t, chartDir, newGenerationDeps)
		writeTestLockFile(t, chartDir, "Chart.lock", newGenerationDeps)
		require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts"), 0o755))
		putArchive(t, filepath.Join(chartDir, "charts"), oldGenerationDeps[0])
		root := seedRecoverWorkspace(t, m, chartDir, txnPhaseCommitted, true, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
			putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
			oldData, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(txn.backupLockPath(), oldData, 0o644))
		})

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assert.FileExists(t, filepath.Join(chartDir, "charts", "signtest-0.1.0.tgz"))
		assert.NoFileExists(t, filepath.Join(chartDir, "charts", "local-subchart-0.1.0.tgz"))
		oldData, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
		require.NoError(t, err)
		actual, err := os.ReadFile(filepath.Join(chartDir, "Chart.lock"))
		require.NoError(t, err)
		assert.Equal(t, oldData, actual)
		assert.NoDirExists(t, root)
	})

	t.Run("7 build committed without lock publishing: accepted", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeGeneration(t, chartDir, "Chart.lock", newGenerationDeps)
		root := seedRecoverWorkspace(t, m, chartDir, txnPhaseCommitted, false, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
			putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
		})

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assertGeneration(t, chartDir, "Chart.lock", newGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("8 corrupt journal: conservative rollback", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeTestChartMetadata(t, chartDir, oldGenerationDeps)
		require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts"), 0o755))
		putArchive(t, filepath.Join(chartDir, "charts"), newGenerationDeps[0])
		root := seedRecoverWorkspace(t, m, chartDir, txnPhasePublishing, true, true, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
			putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
			oldData, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(txn.backupLockPath(), oldData, 0o644))
			require.NoError(t, txn.stageCandidateLock(mustBuildLock(t, newGenerationDeps)))
		})

		require.NoError(t, m.recoverStaleWorkspaces(chartDir))

		assertGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("9a committed first generation without backup accepted", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeGeneration(t, chartDir, "Chart.lock", newGenerationDeps)
		root := seedRecoverWorkspace(t, m, chartDir, txnPhaseCommitted, true, false, func(*dependencyTxn) {})

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assertGeneration(t, chartDir, "Chart.lock", newGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("9b committed broken first generation removed", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeTestChartMetadata(t, chartDir, newGenerationDeps)
		writeTestLockFile(t, chartDir, "Chart.lock", newGenerationDeps)
		require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts"), 0o755))
		putArchive(t, filepath.Join(chartDir, "charts"), oldGenerationDeps[0])
		root := seedRecoverWorkspace(t, m, chartDir, txnPhaseCommitted, true, false, func(*dependencyTxn) {})

		require.NoError(t, m.recoverWorkspace(chartDir, root, mustReadJournal(t, root)))

		assert.NoDirExists(t, filepath.Join(chartDir, "charts"))
		assert.NoFileExists(t, filepath.Join(chartDir, "Chart.lock"))
		assert.NoDirExists(t, root)
	})
}

func TestCommitLiveRollback(t *testing.T) {
	ctx := context.Background()

	t.Run("publishing charts fails: previous charts restored", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		signtestChart, err := loader.LoadDir(ctx, filepath.Join("testdata", "signtest"))
		require.NoError(t, err)
		require.NoError(t, chartutil.SaveDir(signtestChart, chartDir))
		before := snapshotDir(t, chartDir)

		err = m.withDependencyTxn(ctx, func(_ context.Context, txn *dependencyTxn) error {
			prepared, err := txn.prepareCandidate(ctx, oldGenerationDeps)
			if err != nil {
				return err
			}
			installRenameFailure(t, func(src string) bool { return src == txn.candidateChartsDir() })
			return txn.commit(ctx, commitOptions{
				publishLock: false,
				lockName:    "Chart.lock",
				digest:      mustBuildLock(t, prepared).Digest,
				req:         oldGenerationDeps,
				lock:        mustBuildLock(t, prepared),
			})
		})
		require.Error(t, err)
		assert.Equal(t, before, snapshotDir(t, chartDir))
		assert.Empty(t, listTmpWorkspaceEntries(t, chartDir))
	})

	t.Run("publishing lock fails without previous generation: candidate removed", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		signtestChart, err := loader.LoadDir(ctx, filepath.Join("testdata", "signtest"))
		require.NoError(t, err)
		require.NoError(t, chartutil.SaveDir(signtestChart, chartDir))
		writeTestChartMetadata(t, chartDir, oldGenerationDeps)

		err = m.withDependencyTxn(ctx, func(_ context.Context, txn *dependencyTxn) error {
			prepared, err := txn.prepareCandidate(ctx, oldGenerationDeps)
			if err != nil {
				return err
			}
			lock := mustBuildLock(t, prepared)
			if err := txn.stageCandidateLock(lock); err != nil {
				return err
			}
			installRenameFailure(t, func(src string) bool { return src == txn.candidateLockPath() })
			return txn.commit(ctx, commitOptions{
				publishLock: true,
				lockName:    "Chart.lock",
				digest:      lock.Digest,
				req:         oldGenerationDeps,
				lock:        lock,
			})
		})
		require.Error(t, err)
		assert.NoDirExists(t, filepath.Join(chartDir, "charts"))
		assert.NoFileExists(t, filepath.Join(chartDir, "Chart.lock"))
		assert.Empty(t, listTmpWorkspaceEntries(t, chartDir))
	})
}

func TestCommitSymlinkRefusal(t *testing.T) {
	ctx := context.Background()

	t.Run("lock is a symlink", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		signtestChart, err := loader.LoadDir(ctx, filepath.Join("testdata", "signtest"))
		require.NoError(t, err)
		require.NoError(t, chartutil.SaveDir(signtestChart, chartDir))
		dummy := filepath.Join(chartDir, "dummy.txt")
		require.NoError(t, os.WriteFile(dummy, []byte("dummy"), 0o644))
		lockPath := filepath.Join(chartDir, "Chart.lock")
		require.NoError(t, os.Remove(lockPath))
		require.NoError(t, os.Symlink(dummy, lockPath))
		before := snapshotDir(t, chartDir)

		err = m.withDependencyTxn(ctx, func(_ context.Context, txn *dependencyTxn) error {
			prepared, err := txn.prepareCandidate(ctx, oldGenerationDeps)
			if err != nil {
				return err
			}
			lock := mustBuildLock(t, prepared)
			if err := txn.stageCandidateLock(lock); err != nil {
				return err
			}
			return txn.commit(ctx, commitOptions{publishLock: true, lockName: "Chart.lock", digest: lock.Digest, req: oldGenerationDeps, lock: lock})
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "the Chart.lock file is a symlink to")
		assert.Equal(t, before, snapshotDir(t, chartDir))
		assert.Empty(t, listTmpWorkspaceEntries(t, chartDir))
	})

	t.Run("charts is a symlink", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		target := filepath.Join(t.TempDir(), "charts-target")
		require.NoError(t, os.MkdirAll(target, 0o755))
		require.NoError(t, os.Symlink(target, filepath.Join(chartDir, "charts")))

		err := m.withDependencyTxn(ctx, func(context.Context, *dependencyTxn) error {
			t.Fatal("transaction body must not run with a symlinked charts directory")
			return nil
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symbolic link")
		assert.Empty(t, listTmpWorkspaceEntries(t, chartDir))
	})
}

func TestRecoverMixedWorkspaces(t *testing.T) {
	ctx := context.Background()
	chartDir := t.TempDir()
	m := newTestManager(t, chartDir)

	ours := seedRecoverWorkspace(t, m, chartDir, txnPhasePrepared, true, false, func(txn *dependencyTxn) {
		require.NoError(t, os.MkdirAll(txn.candidateChartsDir(), 0o755))
	})
	legacy := filepath.Join(chartDir, "tmpcharts-555")
	require.NoError(t, os.MkdirAll(legacy, 0o755))
	foreign := filepath.Join(chartDir, "tmpcharts-keep")
	require.NoError(t, os.MkdirAll(foreign, 0o755))

	require.NoError(t, m.recoverStaleWorkspaces(chartDir))
	assert.NoDirExists(t, ours)
	assert.NoDirExists(t, legacy)
	assert.DirExists(t, foreign)

	require.NoError(t, m.withDependencyTxn(ctx, func(_ context.Context, txn *dependencyTxn) error {
		require.DirExists(t, txn.candidateChartsDir())
		return nil
	}))
	assert.ElementsMatch(t, []string{"tmpcharts-keep"}, listTmpWorkspaceEntries(t, chartDir))
}

func TestRecoverWorkspaceIOError(t *testing.T) {
	chartDir := t.TempDir()
	m := newTestManager(t, chartDir)
	writeTestChartMetadata(t, chartDir, oldGenerationDeps)
	root := seedRecoverWorkspace(t, m, chartDir, txnPhaseBackingUp, true, false, func(txn *dependencyTxn) {
		require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
		putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
		require.NoError(t, os.MkdirAll(txn.candidateChartsDir(), 0o755))
		putArchive(t, txn.candidateChartsDir(), newGenerationDeps[0])
	})

	require.NoError(t, os.Chmod(root, 0o500))
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	err := m.recoverStaleWorkspaces(chartDir)
	require.Error(t, err)
	assert.DirExists(t, root, "workspace must be preserved when recovery fails")
}

func TestRecoverInterruptedRollbackConverges(t *testing.T) {
	t.Run("charts restored, lock rollback pending", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeTestChartMetadata(t, chartDir, oldGenerationDeps)

		require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts"), 0o755))
		putArchive(t, filepath.Join(chartDir, "charts"), oldGenerationDeps[0])
		oldLockData, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
		require.NoError(t, err)
		newLockData, err := yaml.Marshal(mustBuildLock(t, newGenerationDeps))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.lock"), newLockData, 0o644))

		root := seedRecoverWorkspace(t, m, chartDir, txnPhasePublishing, true, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.orphanChartsDir(), 0o755))
			putArchive(t, txn.orphanChartsDir(), newGenerationDeps[0])
			require.NoError(t, os.WriteFile(txn.backupLockPath(), oldLockData, 0o644))
		})

		require.NoError(t, m.recoverStaleWorkspaces(chartDir))
		assertGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		assert.NoDirExists(t, root)
	})

	t.Run("both slots restored, recovery is idempotent", func(t *testing.T) {
		chartDir := t.TempDir()
		m := newTestManager(t, chartDir)
		writeGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)

		root := seedRecoverWorkspace(t, m, chartDir, txnPhasePublishing, true, false, func(txn *dependencyTxn) {
			require.NoError(t, os.MkdirAll(txn.orphanChartsDir(), 0o755))
			putArchive(t, txn.orphanChartsDir(), newGenerationDeps[0])
			newLockData, err := yaml.Marshal(mustBuildLock(t, newGenerationDeps))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(txn.orphanLockPath(), newLockData, 0o644))
		})

		require.NoError(t, m.recoverStaleWorkspaces(chartDir))
		assertGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
		assert.NoDirExists(t, root)
		require.NoError(t, m.recoverStaleWorkspaces(chartDir))
	})
}

func TestRecoverStagingWorkspaceNeverTouchesMainGeneration(t *testing.T) {
	for _, phase := range []txnPhase{txnPhaseStaging, txnPhasePrepared} {
		t.Run(string(phase), func(t *testing.T) {
			chartDir := t.TempDir()
			m := newTestManager(t, chartDir)
			writeGeneration(t, chartDir, "Chart.lock", oldGenerationDeps)
			before := snapshotDir(t, chartDir)

			root := seedRecoverWorkspace(t, m, chartDir, phase, true, false, func(txn *dependencyTxn) {
				// Empty workspace: interrupted before any rename happened.
			})

			require.NoError(t, m.recoverStaleWorkspaces(chartDir))
			assert.Equal(t, before, snapshotDir(t, chartDir), "main generation must stay byte-identical")
			assert.NoDirExists(t, root)
		})
	}
}

func TestRecoverCommittedDigestMismatchRollsBack(t *testing.T) {
	chartDir := t.TempDir()
	m := newTestManager(t, chartDir)
	writeTestChartMetadata(t, chartDir, newGenerationDeps)

	tamperedLock := mustBuildLock(t, newGenerationDeps)
	tamperedLock.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	tamperedData, err := yaml.Marshal(tamperedLock)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.lock"), tamperedData, 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts"), 0o755))
	putArchive(t, filepath.Join(chartDir, "charts"), newGenerationDeps[0])

	root := seedRecoverWorkspace(t, m, chartDir, txnPhaseCommitted, true, false, func(txn *dependencyTxn) {
		require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
		putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
		oldData, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(txn.backupLockPath(), oldData, 0o644))
	})

	require.NoError(t, m.recoverStaleWorkspaces(chartDir))
	expectedOldLock, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
	require.NoError(t, err)
	restoredLock, err := os.ReadFile(filepath.Join(chartDir, "Chart.lock"))
	require.NoError(t, err)
	assert.Equal(t, expectedOldLock, restoredLock)
	assert.FileExists(t, filepath.Join(chartDir, "charts", "signtest-0.1.0.tgz"))
	assert.NoFileExists(t, filepath.Join(chartDir, "charts", "local-subchart-0.1.0.tgz"))
	assert.NoDirExists(t, root)
}

func TestRecoverCommittedHelmV2HashLock(t *testing.T) {
	srcChart := filepath.Join("..", "cmd", "testdata", "testcharts", "issue-7233")
	srcAlpine := filepath.Join("..", "cmd", "testdata", "testcharts", "alpine")

	root := t.TempDir()
	chartDir := filepath.Join(root, "issue-7233")
	require.NoError(t, fs.CopyDir(srcChart, chartDir))
	require.NoError(t, fs.CopyDir(srcAlpine, filepath.Join(root, "alpine")))

	m := &Manager{
		Out:              io.Discard,
		ChartPath:        chartDir,
		RepositoryConfig: filepath.Join(t.TempDir(), "repositories.yaml"),
		RepositoryCache:  t.TempDir(),
	}

	ws := seedRecoverWorkspace(t, m, chartDir, txnPhaseCommitted, false, false, func(*dependencyTxn) {})

	require.NoError(t, m.recoverStaleWorkspaces(chartDir))
	assert.NoDirExists(t, ws)
	assert.FileExists(t, filepath.Join(chartDir, "charts", "alpine-0.1.0.tgz"))
	assert.FileExists(t, filepath.Join(chartDir, "requirements.lock"))
}

func TestRecoverWorkspaceV1RequirementsLock(t *testing.T) {
	chartDir := t.TempDir()
	m := newTestManager(t, chartDir)

	v1Metadata := &chart.Metadata{
		APIVersion:   chart.APIVersionV1,
		Name:         "parent",
		Version:      "0.1.0",
		Dependencies: newGenerationDeps,
	}
	metadataData, err := yaml.Marshal(v1Metadata)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "requirements.yaml"), metadataData, 0o644))
	lockData, err := yaml.Marshal(mustBuildLock(t, newGenerationDeps))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "requirements.lock"), lockData, 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts"), 0o755))
	putArchive(t, filepath.Join(chartDir, "charts"), newGenerationDeps[0])

	root := seedRecoverWorkspace(t, m, chartDir, txnPhaseCommitted, true, false, func(txn *dependencyTxn) {
		txn.journal.LockName = "requirements.lock"
		require.NoError(t, txn.writeJournal())
		require.NoError(t, os.MkdirAll(txn.backupChartsDir(), 0o755))
		putArchive(t, txn.backupChartsDir(), oldGenerationDeps[0])
		oldData, err := yaml.Marshal(mustBuildLock(t, oldGenerationDeps))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(txn.backupLockPath(), oldData, 0o644))
	})

	require.NoError(t, m.recoverStaleWorkspaces(chartDir))

	assert.FileExists(t, filepath.Join(chartDir, "charts", "local-subchart-0.1.0.tgz"))
	assert.FileExists(t, filepath.Join(chartDir, "requirements.lock"))
	assert.NoFileExists(t, filepath.Join(chartDir, "Chart.lock"))
	assert.NoDirExists(t, root)
}

func mustReadJournal(t *testing.T, root string) *depTxnJournal {
	t.Helper()
	journal, err := readDepTxnJournal(root)
	require.NoError(t, err)
	require.NotNil(t, journal)
	return journal
}

func installRenameFailure(t *testing.T, fail func(src string) bool) {
	t.Helper()
	original := txnRename
	txnRename = func(src, dst string) error {
		if fail(src) {
			return os.ErrPermission
		}
		return original(src, dst)
	}
	t.Cleanup(func() { txnRename = original })
}
