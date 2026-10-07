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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"sigs.k8s.io/yaml"

	"github.com/werf/nelm/v2/pkg/helm/intern/resolver"
	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/loader"
)

func dependencyLockFileName(apiVersion string) string {
	if apiVersion == chart.APIVersionV1 {
		return "requirements.lock"
	}
	return "Chart.lock"
}

func shouldPublishLock(oldLock *chart.Lock, newDigest string) bool {
	return oldLock == nil || oldLock.Digest != newDigest
}

func (t *dependencyTxn) stageCandidateLock(lock *chart.Lock) error {
	data, err := yaml.Marshal(lock)
	if err != nil {
		return fmt.Errorf("marshal dependency lock: %w", err)
	}

	path := t.candidateLockPath()
	info, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect staged dependency lock %q: %w", path, err)
	} else if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("the staged lock file %q is a symbolic link", path)
		}
		return fmt.Errorf("staged dependency lock %q already exists", path)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("stage dependency lock: %w", err)
	}
	return nil
}

// verifyGeneration checks that chartsDir is fully and exactly described by
// lock: the digest matches the Chart.yaml requirements, every repository
// dependency has a regular archive whose chart name and version match the lock,
// every local dependency is an unpacked directory satisfying its constraint,
// and the directory contains no foreign loadable archives.
//
// Local dependencies are always validated against localDepsChartsDir, which
// must point at the current charts directory even when chartsDir is the
// staging candidate: entries carried into the candidate may be relative
// symlinks that only resolve at the final charts depth.
func verifyGeneration(ctx context.Context, chartsDir, localDepsChartsDir string, req []*chart.Dependency, lock *chart.Lock) error {
	if req != nil {
		digest, err := resolver.HashReq(req, lock.Dependencies)
		if err != nil {
			return fmt.Errorf("calculate dependency lock digest: %w", err)
		}
		if digest != lock.Digest {
			return fmt.Errorf("dependency lock digest %q does not match resolved dependencies digest %q", lock.Digest, digest)
		}
	}

	localDepNames := make(map[string]bool)
	expectedArchives := make(map[string]bool)
	for _, dep := range lock.Dependencies {
		if dep.Repository == "" {
			localDepNames[dep.Name] = true
			if err := verifyLocalDependency(ctx, localDepsChartsDir, dep); err != nil {
				return err
			}
			continue
		}
		archiveName := fmt.Sprintf("%s-%s.tgz", dep.Name, dep.Version)
		expectedArchives[archiveName] = true
		if err := verifyArchivedDependency(ctx, chartsDir, dep, archiveName); err != nil {
			return err
		}
	}

	entries, err := os.ReadDir(chartsDir)
	if err != nil {
		return fmt.Errorf("read charts directory %q: %w", chartsDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tgz") {
			continue
		}
		if expectedArchives[entry.Name()] {
			continue
		}
		ch, err := loader.LoadFile(ctx, filepath.Join(chartsDir, entry.Name()))
		if err != nil {
			continue
		}
		if localDepNames[ch.Name()] {
			continue
		}
		return fmt.Errorf("unexpected chart archive %q (%s %s) not described by the dependency lock", entry.Name(), ch.Name(), ch.Metadata.Version)
	}
	return nil
}

func verifyArchivedDependency(ctx context.Context, chartsDir string, dep *chart.Dependency, archiveName string) error {
	archivePath := filepath.Join(chartsDir, archiveName)
	info, err := os.Lstat(archivePath)
	if err != nil {
		return fmt.Errorf("dependency %s archive %q: %w", dep.Name, archiveName, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("dependency %s archive %q is a symbolic link", dep.Name, archiveName)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("dependency %s archive %q is not a regular file", dep.Name, archiveName)
	}

	ch, err := loader.LoadFile(ctx, archivePath)
	if err != nil {
		return fmt.Errorf("verify dependency %s archive %q: %w", dep.Name, archiveName, err)
	}
	if ch.Name() != dep.Name {
		return fmt.Errorf("dependency %s archive %q contains chart %q", dep.Name, archiveName, ch.Name())
	}
	if !versionEquals(dep.Version, ch.Metadata.Version) {
		return fmt.Errorf("dependency %s archive %q contains chart version %q, expected %q", dep.Name, archiveName, ch.Metadata.Version, dep.Version)
	}
	return nil
}

func verifyLocalDependency(ctx context.Context, chartsDir string, dep *chart.Dependency) error {
	ch, err := loader.LoadDir(ctx, filepath.Join(chartsDir, dep.Name))
	if err != nil {
		return fmt.Errorf("load local dependency %q: %w", dep.Name, err)
	}

	constraint, err := semver.NewConstraint(dep.Version)
	if err != nil {
		return fmt.Errorf("dependency %s has an invalid version/constraint format: %w", dep.Name, err)
	}
	v, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return fmt.Errorf("invalid version %s for dependency %s: %w", ch.Metadata.Version, dep.Name, err)
	}
	if !constraint.Check(v) {
		return fmt.Errorf("dependency %s at version %s does not satisfy the constraint %s", dep.Name, ch.Metadata.Version, dep.Version)
	}
	return nil
}
