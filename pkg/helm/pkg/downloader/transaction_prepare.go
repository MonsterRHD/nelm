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
	stdfs "io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/werf/nelm/v2/pkg/helm/intern/third_party/dep/fs"
	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/loader"
	"github.com/werf/nelm/v2/pkg/helm/pkg/getter"
	"github.com/werf/nelm/v2/pkg/helm/pkg/registry"
)

// prepareCandidate builds the complete candidate charts generation inside the
// transaction workspace. The main charts directory and lock file are never
// modified here. The returned dependency slice is a private copy with file://
// dependencies rewritten to their resolved versions.
func (t *dependencyTxn) prepareCandidate(ctx context.Context, deps []*chart.Dependency) ([]*chart.Dependency, error) {
	m := t.m
	prepared := cloneDependencies(deps)

	repos, err := m.loadChartRepositories()
	if err != nil {
		return nil, err
	}

	destPath := t.candidateChartsDir()
	fmt.Fprintf(m.Out, "Saving %d charts\n", len(prepared))

	churls := make(map[string]struct{})
	plannedArchives := make(map[string]bool)
	localDepNames := make(map[string]bool)
	for _, dep := range prepared {
		switch {
		case dep.Repository == "":
			localDepNames[dep.Name] = true
			if err := t.validateLocalDependency(ctx, dep); err != nil {
				return nil, err
			}
		case strings.HasPrefix(dep.Repository, "file://"):
			if m.Debug {
				fmt.Fprintf(m.Out, "Archiving %s from repo %s\n", dep.Name, dep.Repository)
			}
			version, err := tarFromLocalDir(ctx, t.chartPath, dep.Name, dep.Repository, dep.Version, destPath)
			if err != nil {
				return nil, err
			}
			dep.Version = version
			plannedArchives[fmt.Sprintf("%s-%s.tgz", dep.Name, version)] = true
		default:
			churl, username, password, insecureSkipTLSVerify, passCredentialsAll, caFile, certFile, keyFile, err := m.findChartURL(dep.Name, dep.Version, dep.Repository, repos)
			if err != nil {
				return nil, fmt.Errorf("could not find %s: %w", churl, err)
			}
			if _, ok := churls[churl]; ok {
				fmt.Fprintf(m.Out, "Already downloaded %s from repo %s\n", dep.Name, dep.Repository)
				continue
			}
			fmt.Fprintf(m.Out, "Downloading %s from repo %s\n", dep.Name, dep.Repository)

			dl := ChartDownloader{
				Out:              m.Out,
				Verify:           m.Verify,
				Keyring:          m.Keyring,
				RepositoryConfig: m.RepositoryConfig,
				RepositoryCache:  m.RepositoryCache,
				ContentCache:     m.ContentCache,
				RegistryClient:   m.RegistryClient,
				Getters:          m.Getters,
				Options: []getter.Option{
					getter.WithBasicAuth(username, password),
					getter.WithPassCredentialsAll(passCredentialsAll),
					getter.WithInsecureSkipVerifyTLS(insecureSkipTLSVerify),
					getter.WithTLSClientConfig(certFile, keyFile, caFile),
				},
			}

			version := ""
			if registry.IsOCI(churl) {
				churl, version, err = parseOCIRef(churl)
				if err != nil {
					return nil, fmt.Errorf("could not parse OCI reference: %w", err)
				}
				dl.Options = append(dl.Options,
					getter.WithRegistryClient(m.RegistryClient),
					getter.WithTagName(version))
			}

			archivePath, _, err := dl.DownloadTo(churl, version, destPath)
			if err != nil {
				return nil, fmt.Errorf("could not download %s: %w", churl, err)
			}
			plannedArchives[filepath.Base(archivePath)] = true
			churls[churl] = struct{}{}
		}
	}

	if err := keepPlannedCandidateFiles(destPath, plannedArchives); err != nil {
		return nil, err
	}
	fmt.Fprintln(m.Out, "Deleting outdated charts")

	if err := t.carryOverCharts(ctx, localDepNames); err != nil {
		return nil, err
	}
	return prepared, nil
}

// keepPlannedCandidateFiles removes every non-directory entry from the freshly
// downloaded candidate that is not one of the planned chart archives. The old
// per-file move never published provenance files or any other helper artifacts
// created next to downloads.
func keepPlannedCandidateFiles(chartsDir string, plannedArchives map[string]bool) error {
	entries, err := os.ReadDir(chartsDir)
	if err != nil {
		return fmt.Errorf("read candidate charts directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || plannedArchives[entry.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(chartsDir, entry.Name())); err != nil {
			return fmt.Errorf("remove unplanned staged file %q: %w", entry.Name(), err)
		}
	}
	return nil
}

func (t *dependencyTxn) validateLocalDependency(ctx context.Context, dep *chart.Dependency) error {
	fmt.Fprintf(t.m.Out, "Dependency %s did not declare a repository. Assuming it exists in the charts directory\n", dep.Name)

	chartPath := filepath.Join(t.mainChartsDir(), dep.Name)
	ch, err := loader.LoadDir(ctx, chartPath)
	if err != nil {
		return fmt.Errorf("unable to load chart '%s': %w", chartPath, err)
	}

	constraint, err := semver.NewConstraint(dep.Version)
	if err != nil {
		return fmt.Errorf("dependency %s has an invalid version/constraint format: %w", dep.Name, err)
	}

	v, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return fmt.Errorf("invalid version %s for dependency %s: %w", dep.Version, dep.Name, err)
	}

	if !constraint.Check(v) {
		return fmt.Errorf("dependency %s at version %s does not satisfy the constraint %s", dep.Name, ch.Metadata.Version, dep.Version)
	}
	return nil
}

// carryOverCharts preserves entries of the current charts generation that are
// not produced by downloads themselves: all subdirectories (including symlink
// entries), archives of unpacked local dependencies and entries that cannot be
// loaded as charts. Outdated archives are dropped.
func (t *dependencyTxn) carryOverCharts(ctx context.Context, localDepNames map[string]bool) error {
	mainChartsDir := t.mainChartsDir()
	entries, err := os.ReadDir(mainChartsDir)
	if err != nil {
		if errors.Is(err, stdfs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read current charts directory: %w", err)
	}

	candidateChartsDir := t.candidateChartsDir()
	for _, entry := range entries {
		source := filepath.Join(mainChartsDir, entry.Name())
		dest := filepath.Join(candidateChartsDir, entry.Name())

		if _, err := os.Lstat(dest); err == nil {
			continue
		} else if !errors.Is(err, stdfs.ErrNotExist) {
			return fmt.Errorf("inspect candidate charts entry %q: %w", entry.Name(), err)
		}

		if entry.IsDir() {
			if err := fs.CopyDir(source, dest); err != nil {
				return fmt.Errorf("carry over charts subdirectory %q: %w", entry.Name(), err)
			}
			continue
		}

		ch, loadErr := loader.LoadFile(ctx, source)
		if loadErr == nil && !localDepNames[ch.Name()] {
			continue
		}
		if err := fs.CopyFile(source, dest); err != nil {
			return fmt.Errorf("carry over charts entry %q: %w", entry.Name(), err)
		}
	}
	return nil
}

func cloneDependencies(deps []*chart.Dependency) []*chart.Dependency {
	cloned := make([]*chart.Dependency, len(deps))
	for i, dep := range deps {
		depCopy := *dep
		cloned[i] = &depCopy
	}
	return cloned
}
