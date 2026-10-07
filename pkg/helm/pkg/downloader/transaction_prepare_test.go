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
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/loader"
	chartutil "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/util"
	"github.com/werf/nelm/v2/pkg/helm/pkg/getter"
	"github.com/werf/nelm/v2/pkg/helm/pkg/repo/v1/repotest"
)

func newTxnWithWorkspace(t *testing.T, m *Manager, chartPath string) *dependencyTxn {
	t.Helper()
	txn := &dependencyTxn{m: m, chartPath: chartPath}
	root, err := txn.makeWorkspaceDir()
	require.NoError(t, err)
	txn.root = root
	require.NoError(t, os.MkdirAll(txn.candidateChartsDir(), 0o755))
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return txn
}

func snapshotDir(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	_, err := os.Stat(root)
	if os.IsNotExist(err) {
		return snapshot
	}
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		if rel == "." {
			return nil
		}
		info, err := os.Lstat(path)
		require.NoError(t, err)
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			require.NoError(t, err)
			snapshot[rel] = "symlink:" + target
			return nil
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		snapshot[rel] = string(data)
		return nil
	}))
	return snapshot
}

func prepareTestRepoServer(t *testing.T) *repotest.Server {
	t.Helper()
	srv := repotest.NewTempServer(
		t,
		repotest.WithChartSourceGlob("testdata/*.tgz*"),
	)
	require.NoError(t, srv.LinkIndices())
	return srv
}

func TestPrepareCandidateAllSources(t *testing.T) {
	srv := prepareTestRepoServer(t)
	defer srv.Stop()

	dir := func(p ...string) string {
		return filepath.Join(append([]string{srv.Root()}, p...)...)
	}

	fileDepChart := &chart.Chart{
		Metadata: &chart.Metadata{Name: "dep-chart", Version: "0.1.0", APIVersion: "v1"},
	}
	require.NoError(t, chartutil.SaveDir(fileDepChart, dir()))

	localNoRepo := &chart.Chart{
		Metadata: &chart.Metadata{Name: "localno", Version: "0.1.0", APIVersion: "v2"},
	}
	require.NoError(t, chartutil.SaveDir(localNoRepo, dir("with-dependency", "charts")))

	chartPath := dir("with-dependency")
	before := snapshotDir(t, filepath.Join(chartPath, "charts"))
	lockExistedBefore := false
	if _, err := os.Stat(filepath.Join(chartPath, "Chart.lock")); err == nil {
		lockExistedBefore = true
	}
	assert.False(t, lockExistedBefore)

	g := getter.Providers{{Schemes: []string{"http", "https"}, New: getter.NewHTTPGetter}}
	m := &Manager{
		ChartPath:        chartPath,
		Out:              io.Discard,
		Getters:          g,
		RepositoryConfig: dir("repositories.yaml"),
		RepositoryCache:  dir(),
		ContentCache:     t.TempDir(),
	}

	deps := []*chart.Dependency{
		{Name: "local-subchart", Version: "0.1.0", Repository: srv.URL()},
		{Name: "dep-chart", Version: "0.1.0", Repository: "file://../dep-chart"},
		{Name: "localno", Version: "0.1.0"},
	}

	var candidateDir string
	err := m.withDependencyTxn(context.Background(), func(_ context.Context, txn *dependencyTxn) error {
		prepared, err := txn.prepareCandidate(context.Background(), deps)
		require.NoError(t, err)
		candidateDir = txn.candidateChartsDir()

		versions := map[string]string{}
		for _, dep := range prepared {
			versions[dep.Name] = dep.Version
		}
		assert.Equal(t, "0.1.0", versions["local-subchart"])
		assert.Equal(t, "0.1.0", versions["dep-chart"])
		assert.Equal(t, "0.1.0", versions["localno"])

		assert.FileExists(t, filepath.Join(candidateDir, "local-subchart-0.1.0.tgz"))
		assert.FileExists(t, filepath.Join(candidateDir, "dep-chart-0.1.0.tgz"))
		assert.DirExists(t, filepath.Join(candidateDir, "localno"))

		subChart, err := loader.LoadFile(context.Background(), filepath.Join(candidateDir, "local-subchart-0.1.0.tgz"))
		require.NoError(t, err)
		assert.Equal(t, "local-subchart", subChart.Name())
		assert.Equal(t, "0.1.0", subChart.Metadata.Version)
		return nil
	})
	require.NoError(t, err)

	assert.Equal(t, before, snapshotDir(t, filepath.Join(chartPath, "charts")), "main charts must not change during prepare")
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestPrepareCandidateDownloadFailure(t *testing.T) {
	srv := prepareTestRepoServer(t)

	dir := func(p ...string) string {
		return filepath.Join(append([]string{srv.Root()}, p...)...)
	}
	chartPath := dir("with-dependency")
	require.NoError(t, os.MkdirAll(chartPath, 0o755))
	mainCharts := filepath.Join(chartPath, "charts")
	require.NoError(t, os.MkdirAll(mainCharts, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(mainCharts, "signtest-0.1.0.tgz"), readTestFile(t, "testdata/signtest-0.1.0.tgz"), 0o644))
	before := snapshotDir(t, mainCharts)

	g := getter.Providers{{Schemes: []string{"http", "https"}, New: getter.NewHTTPGetter}}
	m := &Manager{
		ChartPath:        chartPath,
		Out:              io.Discard,
		Getters:          g,
		RepositoryConfig: dir("repositories.yaml"),
		RepositoryCache:  dir(),
		ContentCache:     t.TempDir(),
	}

	deps := []*chart.Dependency{{Name: "local-subchart", Version: "0.1.0", Repository: srv.URL()}}

	srv.Stop()
	err := m.withDependencyTxn(context.Background(), func(_ context.Context, txn *dependencyTxn) error {
		_, err := txn.prepareCandidate(context.Background(), deps)
		return err
	})
	require.Error(t, err)
	assert.Equal(t, before, snapshotDir(t, mainCharts))
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestPrepareCandidateFileDependencyMissing(t *testing.T) {
	chartPath := t.TempDir()
	m := newTestManager(t, chartPath)

	deps := []*chart.Dependency{{Name: "ghost", Version: "0.1.0", Repository: "file://../ghost"}}
	err := m.withDependencyTxn(context.Background(), func(_ context.Context, txn *dependencyTxn) error {
		_, err := txn.prepareCandidate(context.Background(), deps)
		return err
	})
	require.Error(t, err)
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestCarryOverCharts(t *testing.T) {
	ctx := context.Background()
	chartPath := t.TempDir()
	mainCharts := filepath.Join(chartPath, "charts")
	require.NoError(t, os.MkdirAll(mainCharts, 0o755))

	require.NoError(t, os.MkdirAll(filepath.Join(mainCharts, "adirectory", "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(mainCharts, "adirectory", "nested", "x.txt"), []byte("nested"), 0o644))

	require.NoError(t, os.WriteFile(filepath.Join(mainCharts, "signtest-0.1.0.tgz"), readTestFile(t, "testdata/signtest-0.1.0.tgz"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(mainCharts, "local-subchart-0.1.0.tgz"), readTestFile(t, "testdata/local-subchart-0.1.0.tgz"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(mainCharts, "signtest-0.1.0.tgz.prov"), readTestFile(t, "testdata/signtest-0.1.0.tgz.prov"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(mainCharts, "README.md"), []byte("readme"), 0o644))

	targetDir := filepath.Join(chartPath, "linked-target")
	require.NoError(t, os.MkdirAll(targetDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "y.txt"), []byte("y"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join("..", "linked-target"), filepath.Join(mainCharts, "linked")))

	m := newTestManager(t, chartPath)
	txn := newTxnWithWorkspace(t, m, chartPath)

	require.NoError(t, txn.carryOverCharts(ctx, map[string]bool{"local-subchart": true}))

	candidate := txn.candidateChartsDir()
	assert.NoDirExists(t, filepath.Join(candidate, "signtest-0.1.0.tgz"), "outdated tgz must not be carried over")
	assert.FileExists(t, filepath.Join(candidate, "local-subchart-0.1.0.tgz"))
	assert.FileExists(t, filepath.Join(candidate, "signtest-0.1.0.tgz.prov"))
	assert.FileExists(t, filepath.Join(candidate, "README.md"))
	assert.FileExists(t, filepath.Join(candidate, "adirectory", "nested", "x.txt"))

	linkInfo, err := os.Lstat(filepath.Join(candidate, "linked"))
	require.NoError(t, err)
	assert.True(t, linkInfo.Mode()&os.ModeSymlink != 0)
	target, err := os.Readlink(filepath.Join(candidate, "linked"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("..", "linked-target"), target)
}

func TestPrepareCandidateFileDependencyVersionRewrite(t *testing.T) {
	chartPath := t.TempDir()
	signtestChart, err := loader.LoadDir(context.Background(), filepath.Join("testdata", "signtest"))
	require.NoError(t, err)
	require.NoError(t, chartutil.SaveDir(signtestChart, filepath.Join(chartPath, "testdata")))

	m := newTestManager(t, chartPath)
	dep := &chart.Dependency{
		Name:       signtestChart.Name(),
		Repository: "file://./testdata/signtest",
		Version:    ">=0.1.0",
	}
	depBefore := *dep

	err = m.withDependencyTxn(context.Background(), func(_ context.Context, txn *dependencyTxn) error {
		prepared, err := txn.prepareCandidate(context.Background(), []*chart.Dependency{dep})
		require.NoError(t, err)
		require.Len(t, prepared, 1)
		assert.Equal(t, "0.1.0", prepared[0].Version)
		assert.FileExists(t, filepath.Join(txn.candidateChartsDir(), "signtest-0.1.0.tgz"))
		return nil
	})
	require.NoError(t, err)

	assert.Equal(t, depBefore, *dep, "prepare must not mutate the caller-provided dependency")
}

func TestPrepareCandidateBadLocalDependencyName(t *testing.T) {
	chartPath := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(chartPath, "testdata", "bad-local-subchart"), 0o755))
	badChartYaml := `apiVersion: v2
description: A Helm chart for Kubernetes
name: ../bad-local-subchart
version: 0.1.0`
	require.NoError(t, os.WriteFile(filepath.Join(chartPath, "testdata", "bad-local-subchart", "Chart.yaml"), []byte(badChartYaml), 0o644))

	m := newTestManager(t, chartPath)
	dep := &chart.Dependency{Name: "../bad-local-subchart", Version: "0.1.0", Repository: "file://./testdata/bad-local-subchart"}

	err := m.withDependencyTxn(context.Background(), func(_ context.Context, txn *dependencyTxn) error {
		_, err := txn.prepareCandidate(context.Background(), []*chart.Dependency{dep})
		return err
	})
	require.Error(t, err)
	_, err = os.Stat(filepath.Join(chartPath, "charts"))
	assert.True(t, os.IsNotExist(err))
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestKeepPlannedCandidateFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "chart-0.1.0.tgz"), []byte("archive"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "chart-0.1.0.tgz.prov"), []byte("prov"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "unpacked"), 0o755))

	require.NoError(t, keepPlannedCandidateFiles(dir, map[string]bool{"chart-0.1.0.tgz": true}))

	assert.FileExists(t, filepath.Join(dir, "chart-0.1.0.tgz"))
	assert.NoFileExists(t, filepath.Join(dir, "chart-0.1.0.tgz.prov"))
	assert.DirExists(t, filepath.Join(dir, "unpacked"))
}

func readTestFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	return data
}
