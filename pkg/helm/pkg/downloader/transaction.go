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
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	stdfs "io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gofrs/flock"

	"github.com/werf/nelm/v2/pkg/helm/pkg/helmpath"
)

const (
	depTxnPrefix   = "tmpcharts-"
	depTxnLocksDir = "nelm-dependency-locks"

	depTxnJournalFile       = "journal.json"
	depTxnCandidateCharts   = "charts"
	depTxnCandidateLock     = "lock"
	depTxnBackupCharts      = "charts.bak"
	depTxnBackupLock        = "lock.bak"
	depTxnOrphanCharts      = "orphan-charts"
	depTxnOrphanLock        = "orphan-lock"
	depTxnJournalTmpSuffix  = ".tmp"
	depTxnLockRetryInterval = 100 * time.Millisecond
)

type txnPhase string

const (
	txnPhaseStaging    txnPhase = "staging"
	txnPhasePrepared   txnPhase = "prepared"
	txnPhaseBackingUp  txnPhase = "backing-up"
	txnPhasePublishing txnPhase = "publishing"
	txnPhaseCommitted  txnPhase = "committed"
)

type depTxnJournal struct {
	Version     int       `json:"version"`
	Phase       txnPhase  `json:"phase"`
	PublishLock bool      `json:"publishLock"`
	LockName    string    `json:"lockName"`
	Digest      string    `json:"digest"`
	PID         int       `json:"pid"`
	StartedAt   time.Time `json:"startedAt"`
}

type dependencyTxn struct {
	m         *Manager
	chartPath string
	fileLock  *flock.Flock

	root          string
	journal       *depTxnJournal
	keepWorkspace bool
}

func (t *dependencyTxn) candidateChartsDir() string {
	return filepath.Join(t.root, depTxnCandidateCharts)
}

func (t *dependencyTxn) candidateLockPath() string {
	return filepath.Join(t.root, depTxnCandidateLock)
}

func (t *dependencyTxn) backupChartsDir() string {
	return filepath.Join(t.root, depTxnBackupCharts)
}

func (t *dependencyTxn) backupLockPath() string {
	return filepath.Join(t.root, depTxnBackupLock)
}

func (t *dependencyTxn) orphanChartsDir() string {
	return filepath.Join(t.root, depTxnOrphanCharts)
}

func (t *dependencyTxn) orphanLockPath() string {
	return filepath.Join(t.root, depTxnOrphanLock)
}

func (t *dependencyTxn) mainChartsDir() string {
	return filepath.Join(t.chartPath, "charts")
}

func (t *dependencyTxn) mainLockPath() string {
	return filepath.Join(t.chartPath, t.journal.LockName)
}

func (t *dependencyTxn) writeJournal() error {
	data, err := json.MarshalIndent(t.journal, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dependency transaction journal: %w", err)
	}

	tmpPath := filepath.Join(t.root, depTxnJournalFile+depTxnJournalTmpSuffix)
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write dependency transaction journal: %w", err)
	}
	if err := syncFileAt(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(t.root, depTxnJournalFile)); err != nil {
		return fmt.Errorf("commit dependency transaction journal: %w", err)
	}
	if err := syncDir(t.root); err != nil {
		fmt.Fprintf(t.m.Out, "Warning: unable to sync dependency transaction journal: %s\n", err)
	}
	return nil
}

func syncFileAt(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %q for sync: %w", path, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %q: %w", path, err)
	}
	return nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory %q for sync: %w", path, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync directory %q: %w", path, err)
	}
	return nil
}

func (t *dependencyTxn) setPhase(phase txnPhase) error {
	t.journal.Phase = phase
	if err := t.writeJournal(); err != nil {
		return err
	}
	return nil
}

func (t *dependencyTxn) create() (retErr error) {
	root, err := t.makeWorkspaceDir()
	if err != nil {
		return err
	}
	t.root = root
	defer func() {
		if retErr == nil {
			return
		}
		if err := os.RemoveAll(root); err != nil {
			fmt.Fprintf(t.m.Out, "Warning: unable to remove dependency transaction workspace %q: %s\n", root, err)
		}
		t.root = ""
	}()

	t.journal = &depTxnJournal{
		Version:   1,
		Phase:     txnPhaseStaging,
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC(),
	}
	if err := t.writeJournal(); err != nil {
		return err
	}
	if err := os.MkdirAll(t.candidateChartsDir(), 0o755); err != nil {
		return fmt.Errorf("create candidate charts directory: %w", err)
	}
	return nil
}

func (t *dependencyTxn) makeWorkspaceDir() (string, error) {
	for range 5 {
		root := filepath.Join(t.chartPath, depTxnPrefix+workspaceSuffix())
		err := os.Mkdir(root, 0o755)
		if err == nil {
			return root, nil
		}
		if !errors.Is(err, stdfs.ErrExist) {
			return "", fmt.Errorf("create dependency transaction workspace: %w", err)
		}
	}
	return "", errors.New("create dependency transaction workspace: exhausted unique name attempts")
}

func (t *dependencyTxn) cleanup() {
	if t.root == "" {
		return
	}
	if err := os.RemoveAll(t.root); err != nil {
		fmt.Fprintf(t.m.Out, "Warning: unable to remove dependency transaction workspace %q: %s\n", t.root, err)
	}
}

func (t *dependencyTxn) releaseLock() {
	if t.fileLock != nil {
		if err := t.fileLock.Unlock(); err != nil {
			fmt.Fprintf(t.m.Out, "Warning: unable to release dependency lock: %s\n", err)
		}
	}
}

func workspaceSuffix() string {
	var b [4]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%d-%d-%x", os.Getpid(), time.Now().UnixNano(), b[:])
}

func (m *Manager) dependencyLockPath(absChartPath string) (string, error) {
	cacheDir := m.RepositoryCache
	if cacheDir == "" {
		cacheDir = helmpath.CachePath("repository")
	}
	sum, err := key(absChartPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, depTxnLocksDir, sum+".lock"), nil
}

// withDependencyLock serializes the whole operation, rejects unsupported
// charts paths and recovers interrupted workspaces, but creates no workspace.
func (m *Manager) withDependencyLock(ctx context.Context, run func(ctx context.Context, txn *dependencyTxn) error) error {
	txn, err := m.beginDependencyTxn(ctx)
	if err != nil {
		return err
	}
	defer txn.releaseLock()

	if err := m.validateMainChartsPath(txn.chartPath); err != nil {
		return err
	}
	if err := m.recoverStaleWorkspaces(txn.chartPath); err != nil {
		return err
	}
	return run(ctx, txn)
}

func (m *Manager) withDependencyTxn(ctx context.Context, run func(ctx context.Context, txn *dependencyTxn) error) error {
	return m.withDependencyLock(ctx, func(ctx context.Context, txn *dependencyTxn) error {
		if err := txn.create(); err != nil {
			return err
		}
		if err := run(ctx, txn); err != nil {
			if !txn.keepWorkspace {
				txn.cleanup()
			}
			return err
		}
		if !txn.keepWorkspace {
			txn.cleanup()
		}
		return nil
	})
}

func (m *Manager) validateMainChartsPath(absChartPath string) error {
	chartsPath := filepath.Join(absChartPath, "charts")
	info, err := os.Lstat(chartsPath)
	if err != nil {
		if errors.Is(err, stdfs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect charts directory %q: %w", chartsPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q is a symbolic link; dependency updates do not support a symlinked charts directory", chartsPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", chartsPath)
	}
	return nil
}

func (m *Manager) beginDependencyTxn(ctx context.Context) (*dependencyTxn, error) {
	absChartPath, err := filepath.Abs(m.ChartPath)
	if err != nil {
		return nil, fmt.Errorf("resolve chart path %q: %w", m.ChartPath, err)
	}

	lockPath, err := m.dependencyLockPath(absChartPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, fmt.Errorf("create dependency lock directory: %w", err)
	}

	fileLock := flock.New(lockPath)
	locked, err := fileLock.TryLockContext(ctx, depTxnLockRetryInterval)
	if err != nil {
		return nil, fmt.Errorf("acquire dependency lock for %q: %w", m.ChartPath, err)
	}
	if !locked {
		return nil, fmt.Errorf("acquire dependency lock for %q", m.ChartPath)
	}

	return &dependencyTxn{
		m:         m,
		chartPath: absChartPath,
		fileLock:  fileLock,
	}, nil
}

type staleWorkspaceKind int

const (
	staleWorkspaceOurs staleWorkspaceKind = iota
	staleWorkspaceLegacy
	staleWorkspaceForeign
)

var (
	currentWorkspaceNameRe = regexp.MustCompile(`^tmpcharts-\d+-\d+-[0-9a-f]+$`)
	legacyWorkspaceNameRe  = regexp.MustCompile(`^tmpcharts-\d+$`)
)

func classifyStaleWorkspace(path string) (staleWorkspaceKind, *depTxnJournal) {
	name := filepath.Base(path)
	journal, err := readDepTxnJournal(path)
	if err == nil && journal != nil && journal.Version == 1 {
		return staleWorkspaceOurs, journal
	}
	if currentWorkspaceNameRe.MatchString(name) {
		return staleWorkspaceOurs, journal
	}
	if legacyWorkspaceNameRe.MatchString(name) {
		return staleWorkspaceLegacy, nil
	}
	return staleWorkspaceForeign, nil
}

func readDepTxnJournal(workspaceDir string) (*depTxnJournal, error) {
	data, err := os.ReadFile(filepath.Join(workspaceDir, depTxnJournalFile))
	if err != nil {
		if errors.Is(err, stdfs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read dependency transaction journal: %w", err)
	}

	journal := new(depTxnJournal)
	if err := json.Unmarshal(data, journal); err != nil {
		return nil, fmt.Errorf("parse dependency transaction journal: %w", err)
	}
	return journal, nil
}

func (m *Manager) recoverStaleWorkspaces(absChartPath string) error {
	entries, err := os.ReadDir(absChartPath)
	if err != nil {
		return fmt.Errorf("scan chart directory for stale dependency workspaces: %w", err)
	}

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), depTxnPrefix) {
			continue
		}
		workspacePath := filepath.Join(absChartPath, entry.Name())

		if !entry.IsDir() {
			fmt.Fprintf(m.Out, "Warning: %q matches the temporary dependency workspace pattern but is not a directory, skipping\n", workspacePath)
			continue
		}

		kind, journal := classifyStaleWorkspace(workspacePath)
		switch kind {
		case staleWorkspaceLegacy:
			if err := txnRemoveAll(workspacePath); err != nil {
				return fmt.Errorf("remove stale dependency workspace %q: %w", workspacePath, err)
			}
		case staleWorkspaceOurs:
			if err := m.recoverWorkspace(absChartPath, workspacePath, journal); err != nil {
				return err
			}
		case staleWorkspaceForeign:
			fmt.Fprintf(m.Out, "Warning: unrecognized directory %q matches the temporary dependency workspace pattern, skipping\n", workspacePath)
		}
	}
	return nil
}
