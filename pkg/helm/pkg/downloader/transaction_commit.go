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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"

	"github.com/werf/nelm/v2/pkg/helm/intern/resolver"
	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/loader"
)

var (
	txnRename    = os.Rename
	txnRemoveAll = os.RemoveAll
)

type commitOptions struct {
	publishLock bool
	lockName    string
	digest      string
	req         []*chart.Dependency
	lock        *chart.Lock
}

func (t *dependencyTxn) commit(ctx context.Context, opts commitOptions) error {
	t.journal.LockName = opts.lockName
	t.journal.PublishLock = opts.publishLock
	t.journal.Digest = opts.digest

	if err := t.preflightCommitTargets(opts); err != nil {
		return err
	}

	if err := t.setPhase(txnPhaseBackingUp); err != nil {
		return err
	}
	if err := t.backupCurrentGeneration(opts); err != nil {
		return t.failCommit(err, opts)
	}

	if err := t.setPhase(txnPhasePublishing); err != nil {
		return t.failCommit(err, opts)
	}
	if err := t.publishCandidate(opts); err != nil {
		return t.failCommit(err, opts)
	}

	if err := t.setPhase(txnPhaseCommitted); err != nil {
		return t.failCommit(err, opts)
	}
	if err := t.verifyCommittedGeneration(ctx, opts); err != nil {
		return t.failCommit(fmt.Errorf("verify committed dependency generation: %w", err), opts)
	}

	if err := txnRemoveAll(t.root); err != nil {
		return fmt.Errorf("remove committed dependency transaction workspace %q: %w", t.root, err)
	}
	t.root = ""
	return nil
}

func (t *dependencyTxn) failCommit(commitErr error, opts commitOptions) error {
	if err := t.restoreGeneration(opts.publishLock); err != nil {
		t.keepWorkspace = true
		return errors.Join(commitErr, fmt.Errorf("rollback dependency generation: %w", err))
	}
	return fmt.Errorf("commit dependency generation: %w", commitErr)
}

func (t *dependencyTxn) preflightCommitTargets(opts commitOptions) error {
	chartsPath := t.mainChartsDir()
	info, err := os.Lstat(chartsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect charts directory %q: %w", chartsPath, err)
	}
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%q is a symbolic link; dependency updates do not support a symlinked charts directory", chartsPath)
		}
		if !info.IsDir() {
			return fmt.Errorf("%q is not a directory", chartsPath)
		}
	}

	if !opts.publishLock {
		return nil
	}
	lockPath := t.mainLockPath()
	if err := checkLockFilePath(lockPath, opts.lockName); err != nil {
		return err
	}
	return nil
}

func checkLockFilePath(lockPath, lockName string) error {
	info, err := os.Lstat(lockPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error getting info for %q: %w", lockPath, err)
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		link, readErr := os.Readlink(lockPath)
		if readErr != nil {
			return fmt.Errorf("error reading symlink for %q: %w", lockPath, readErr)
		}
		return fmt.Errorf("the %s file is a symlink to %q", lockName, link)
	}
	return nil
}

func (t *dependencyTxn) backupCurrentGeneration(opts commitOptions) error {
	if _, err := os.Lstat(t.mainChartsDir()); err == nil {
		if err := txnRename(t.mainChartsDir(), t.backupChartsDir()); err != nil {
			return fmt.Errorf("back up charts directory: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect charts directory: %w", err)
	}

	if !opts.publishLock {
		return nil
	}
	if _, err := os.Lstat(t.mainLockPath()); err == nil {
		if err := txnRename(t.mainLockPath(), t.backupLockPath()); err != nil {
			return fmt.Errorf("back up %s: %w", opts.lockName, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s: %w", opts.lockName, err)
	}
	return nil
}

func (t *dependencyTxn) publishCandidate(opts commitOptions) error {
	if err := txnRename(t.candidateChartsDir(), t.mainChartsDir()); err != nil {
		return fmt.Errorf("publish candidate charts directory: %w", err)
	}
	if !opts.publishLock {
		return nil
	}
	if err := txnRename(t.candidateLockPath(), t.mainLockPath()); err != nil {
		return fmt.Errorf("publish candidate %s: %w", opts.lockName, err)
	}
	return nil
}

func (t *dependencyTxn) verifyCommittedGeneration(ctx context.Context, opts commitOptions) error {
	committedLock := opts.lock
	if opts.publishLock {
		data, err := os.ReadFile(t.mainLockPath())
		if err != nil {
			return fmt.Errorf("read published %s: %w", opts.lockName, err)
		}
		committedLock = new(chart.Lock)
		if err := yaml.Unmarshal(data, committedLock); err != nil {
			return fmt.Errorf("parse published %s: %w", opts.lockName, err)
		}
		if committedLock.Digest != opts.lock.Digest {
			return fmt.Errorf("published %s digest %q does not match candidate digest %q", opts.lockName, committedLock.Digest, opts.lock.Digest)
		}
	}
	return verifyGeneration(ctx, t.mainChartsDir(), t.mainChartsDir(), opts.req, committedLock)
}

// restoreGeneration reconstructs a coherent generation from the observable
// on-disk state. It is shared by live rollback and crash recovery and never
// trusts in-memory state.
func (t *dependencyTxn) restoreGeneration(publishLock bool) error {
	if err := restoreEntry(t.mainChartsDir(), t.candidateChartsDir(), t.backupChartsDir(), t.orphanChartsDir()); err != nil {
		return fmt.Errorf("restore charts directory: %w", err)
	}
	if !publishLock {
		return nil
	}
	if err := restoreEntry(t.mainLockPath(), t.candidateLockPath(), t.backupLockPath(), t.orphanLockPath()); err != nil {
		return fmt.Errorf("restore %s: %w", t.journal.LockName, err)
	}
	return nil
}

// restoreEntry reconciles one committed slot from the presence of its
// candidate, backup and main paths.
func restoreEntry(mainPath, candidatePath, backupPath, orphanPath string) error {
	candidateExists, err := pathExists(candidatePath)
	if err != nil {
		return err
	}
	mainExists, err := pathExists(mainPath)
	if err != nil {
		return err
	}
	backupExists, err := pathExists(backupPath)
	if err != nil {
		return err
	}

	if candidateExists {
		if !mainExists {
			if backupExists {
				if err := txnRename(backupPath, mainPath); err != nil {
					return fmt.Errorf("restore backup %q: %w", backupPath, err)
				}
			}
			return nil
		}
		if backupExists {
			return fmt.Errorf("ambiguous transaction state for %q: current generation, backup and candidate all exist", mainPath)
		}
		return nil
	}

	if mainExists {
		if backupExists {
			if err := quarantine(mainPath, orphanPath); err != nil {
				return err
			}
			if err := txnRename(backupPath, mainPath); err != nil {
				return fmt.Errorf("restore backup %q: %w", backupPath, err)
			}
			return nil
		}
		// No backup means no previous generation. If the quarantine slot
		// already holds a candidate, a previous rollback restored this slot
		// and was interrupted afterwards: main is the coherent generation and
		// recovery must converge instead of renaming into the non-empty slot.
		orphanExists, err := pathExists(orphanPath)
		if err != nil {
			return err
		}
		if orphanExists {
			return nil
		}
		if err := quarantine(mainPath, orphanPath); err != nil {
			return err
		}
		return nil
	}

	if backupExists {
		if err := txnRename(backupPath, mainPath); err != nil {
			return fmt.Errorf("restore backup %q: %w", backupPath, err)
		}
	}
	return nil
}

func quarantine(mainPath, orphanPath string) error {
	if err := txnRename(mainPath, orphanPath); err != nil {
		return fmt.Errorf("quarantine published candidate %q: %w", mainPath, err)
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("inspect %q: %w", path, err)
}

func detectLockName(absChartPath string) string {
	if _, err := os.Stat(filepath.Join(absChartPath, "Chart.lock")); err == nil {
		return "Chart.lock"
	}
	if _, err := os.Stat(filepath.Join(absChartPath, "requirements.lock")); err == nil {
		return "requirements.lock"
	}
	return "Chart.lock"
}

func (m *Manager) recoverWorkspace(absChartPath, workspacePath string, journal *depTxnJournal) error {
	t := &dependencyTxn{
		m:         m,
		chartPath: absChartPath,
		root:      workspacePath,
		journal:   journal,
	}
	readableJournal := journal != nil
	if journal == nil {
		// Unreadable journal: take the conservative path and assume renames
		// may already have happened.
		journal = &depTxnJournal{Version: 1, Phase: txnPhaseBackingUp}
	}
	t.journal = journal
	if t.journal.LockName == "" {
		t.journal.LockName = detectLockName(absChartPath)
	}

	// With a readable journal, no rename happens before the backing-up phase:
	// a staging/prepared workspace never touched the charts directory or
	// lock, so its contents are an unpublished candidate to discard.
	if readableJournal && (t.journal.Phase == txnPhaseStaging || t.journal.Phase == txnPhasePrepared) {
		if err := txnRemoveAll(workspacePath); err != nil {
			return fmt.Errorf("remove stale dependency workspace %q: %w", workspacePath, err)
		}
		return nil
	}

	managedLock := t.journal.PublishLock
	if !managedLock {
		candidateLockExists, err := pathExists(t.candidateLockPath())
		if err != nil {
			return fmt.Errorf("recover stale dependency workspace %q: %w", workspacePath, err)
		}
		backupLockExists, err := pathExists(t.backupLockPath())
		if err != nil {
			return fmt.Errorf("recover stale dependency workspace %q: %w", workspacePath, err)
		}
		managedLock = candidateLockExists || backupLockExists
	}

	if t.journal.Phase == txnPhaseCommitted && t.committedGenerationIsVerified() == nil {
		if err := txnRemoveAll(workspacePath); err != nil {
			return fmt.Errorf("remove recovered dependency workspace %q: %w", workspacePath, err)
		}
		return nil
	}

	if err := t.restoreGeneration(managedLock); err != nil {
		return fmt.Errorf("recover stale dependency workspace %q: %w", workspacePath, err)
	}
	if err := txnRemoveAll(workspacePath); err != nil {
		return fmt.Errorf("remove recovered dependency workspace %q: %w", workspacePath, err)
	}
	return nil
}

// committedGenerationIsVerified re-validates the published charts directory
// against the current Chart.yaml and on-disk lock. The on-disk digest is
// checked strictly, with the Helm v2 hash fallback for apiVersion v1 charts,
// both computed with the same alias handling as Build.
func (t *dependencyTxn) committedGenerationIsVerified() error {
	c, err := loader.LoadDir(context.Background(), t.chartPath)
	if err != nil {
		return err
	}
	if c.Lock == nil {
		return fmt.Errorf("no lock file present")
	}

	req := cloneDependencies(c.Metadata.Dependencies)

	var v2Digest string
	if c.Metadata.APIVersion == chart.APIVersionV1 {
		v2Digest, err = resolver.HashV2Req(req)
		if err != nil {
			return fmt.Errorf("calculate helm v2 dependency lock digest: %w", err)
		}
	}
	if _, err := t.m.resolveRepoNames(req); err != nil {
		return err
	}
	v3Digest, err := resolver.HashReq(req, c.Lock.Dependencies)
	if err != nil {
		return err
	}
	if v3Digest != c.Lock.Digest && (v2Digest == "" || v2Digest != c.Lock.Digest) {
		return fmt.Errorf("dependency lock digest %q matches neither resolved dependencies nor the helm v2 digest", c.Lock.Digest)
	}

	return verifyGeneration(context.Background(), t.mainChartsDir(), t.mainChartsDir(), nil, c.Lock)
}
