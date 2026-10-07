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
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/loader"
	chartutil "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/util"
)

func newFileDependencyChart(t *testing.T, apiVersion string) string {
	t.Helper()
	chartPath := t.TempDir()

	signtestChart, err := loader.LoadDir(context.Background(), filepath.Join("testdata", "signtest"))
	require.NoError(t, err)
	require.NoError(t, chartutil.SaveDir(signtestChart, chartPath))

	md := &chart.Metadata{
		APIVersion:   apiVersion,
		Name:         "with-dependency",
		Version:      "0.1.0",
		Dependencies: []*chart.Dependency{{Name: "signtest", Version: "0.1.0", Repository: "file://./signtest"}},
	}

	if apiVersion == chart.APIVersionV1 {
		data, err := yaml.Marshal(md)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(chartPath, "requirements.yaml"), data, 0o644))
	} else {
		require.NoError(t, chartutil.SaveChartfile(filepath.Join(chartPath, "Chart.yaml"), md))
	}
	return chartPath
}

func pathIdentity(t *testing.T, path string) (uint64, time.Time) {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return st.Ino, fi.ModTime()
}

func TestBuildDoesNotRewriteLock(t *testing.T) {
	ctx := context.Background()
	chartPath := newFileDependencyChart(t, chart.APIVersionV2)
	m := &Manager{
		Out:              io.Discard,
		RepositoryConfig: repoConfig,
		RepositoryCache:  tempRepoCache(t),
		ChartPath:        chartPath,
		SkipUpdate:       true,
	}

	require.NoError(t, m.Update(ctx))
	lockPath := filepath.Join(chartPath, "Chart.lock")
	lockInodeBefore, lockMtimeBefore := pathIdentity(t, lockPath)

	require.NoError(t, m.Build(ctx))
	lockInodeAfter, lockMtimeAfter := pathIdentity(t, lockPath)

	assert.Equal(t, lockInodeBefore, lockInodeAfter, "build must not replace the lock file")
	assert.Equal(t, lockMtimeBefore, lockMtimeAfter, "build must not touch lock mtime")
	assert.FileExists(t, filepath.Join(chartPath, "charts", "signtest-0.1.0.tgz"))
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))

	mdBytes, err := os.ReadFile(filepath.Join(chartPath, "Chart.yaml"))
	require.NoError(t, err)
	md := new(chart.Metadata)
	require.NoError(t, yaml.Unmarshal(mdBytes, md))
	md.Dependencies[0].Version = ">=9.0.0"
	require.NoError(t, chartutil.SaveChartfile(filepath.Join(chartPath, "Chart.yaml"), md))

	err = m.Build(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of sync")
	lockInodeFinal, _ := pathIdentity(t, lockPath)
	assert.Equal(t, lockInodeBefore, lockInodeFinal, "failed build must not touch the lock file")
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestUpdateWithUnchangedDigestKeepsLock(t *testing.T) {
	ctx := context.Background()
	chartPath := newFileDependencyChart(t, chart.APIVersionV2)
	m := &Manager{
		Out:              io.Discard,
		RepositoryConfig: repoConfig,
		RepositoryCache:  tempRepoCache(t),
		ChartPath:        chartPath,
		SkipUpdate:       true,
	}

	require.NoError(t, m.Update(ctx))
	lockPath := filepath.Join(chartPath, "Chart.lock")
	lockInodeBefore, lockMtimeBefore := pathIdentity(t, lockPath)

	require.NoError(t, m.Update(ctx))
	lockInodeAfter, lockMtimeAfter := pathIdentity(t, lockPath)

	assert.Equal(t, lockInodeBefore, lockInodeAfter, "update with unchanged digest must not replace lock")
	assert.Equal(t, lockMtimeBefore, lockMtimeAfter)
	assert.FileExists(t, filepath.Join(chartPath, "charts", "signtest-0.1.0.tgz"))
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestV1RequirementsLockGeneration(t *testing.T) {
	ctx := context.Background()
	chartPath := newFileDependencyChart(t, chart.APIVersionV1)
	m := &Manager{
		Out:              io.Discard,
		RepositoryConfig: repoConfig,
		RepositoryCache:  tempRepoCache(t),
		ChartPath:        chartPath,
		SkipUpdate:       true,
	}

	require.NoError(t, m.Update(ctx))
	assert.FileExists(t, filepath.Join(chartPath, "requirements.lock"))
	assert.NoFileExists(t, filepath.Join(chartPath, "Chart.lock"))
	assert.FileExists(t, filepath.Join(chartPath, "charts", "signtest-0.1.0.tgz"))

	lockInodeBefore, _ := pathIdentity(t, filepath.Join(chartPath, "requirements.lock"))
	require.NoError(t, m.Build(ctx))
	lockInodeAfter, _ := pathIdentity(t, filepath.Join(chartPath, "requirements.lock"))
	assert.Equal(t, lockInodeBefore, lockInodeAfter, "v1 build must not rewrite requirements.lock")

	loaded, err := loader.LoadDir(ctx, chartPath)
	require.NoError(t, err)
	require.NotNil(t, loaded.Lock)
	require.NoError(t, verifyGeneration(ctx, filepath.Join(chartPath, "charts"), filepath.Join(chartPath, "charts"), loaded.Metadata.Dependencies, loaded.Lock))
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}

func TestUpdateWithoutDependenciesRecoversAndNoop(t *testing.T) {
	ctx := context.Background()
	chartPath := t.TempDir()
	require.NoError(t, chartutil.SaveChartfile(filepath.Join(chartPath, "Chart.yaml"), &chart.Metadata{
		APIVersion: chart.APIVersionV2,
		Name:       "no-dependencies",
		Version:    "0.1.0",
	}))

	legacy := filepath.Join(chartPath, "tmpcharts-4242")
	require.NoError(t, os.MkdirAll(legacy, 0o755))

	m := &Manager{
		Out:              io.Discard,
		RepositoryConfig: repoConfig,
		RepositoryCache:  tempRepoCache(t),
		ChartPath:        chartPath,
		SkipUpdate:       true,
	}

	require.NoError(t, m.Update(ctx))
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath), "legacy workspaces must be recovered even without dependencies")
	_, err := os.Stat(filepath.Join(chartPath, "Chart.lock"))
	assert.True(t, os.IsNotExist(err))
}

func TestUpdateAndBuildWithSymlinkedLocalDependency(t *testing.T) {
	ctx := context.Background()
	chartPath := newFileDependencyChart(t, chart.APIVersionV2)

	linkedTarget := &chart.Chart{Metadata: &chart.Metadata{
		APIVersion: chart.APIVersionV2,
		Name:       "linked",
		Version:    "0.1.0",
	}}
	require.NoError(t, chartutil.SaveDir(linkedTarget, chartPath))

	mdBytes, err := os.ReadFile(filepath.Join(chartPath, "Chart.yaml"))
	require.NoError(t, err)
	md := new(chart.Metadata)
	require.NoError(t, yaml.Unmarshal(mdBytes, md))
	md.Dependencies = append(md.Dependencies, &chart.Dependency{Name: "linked", Version: "0.1.0"})
	require.NoError(t, chartutil.SaveChartfile(filepath.Join(chartPath, "Chart.yaml"), md))

	require.NoError(t, os.MkdirAll(filepath.Join(chartPath, "charts"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join("..", "linked"), filepath.Join(chartPath, "charts", "linked")))

	m := &Manager{
		Out:              io.Discard,
		RepositoryConfig: repoConfig,
		RepositoryCache:  tempRepoCache(t),
		ChartPath:        chartPath,
		SkipUpdate:       true,
	}

	require.NoError(t, m.Update(ctx))

	linkInfo, err := os.Lstat(filepath.Join(chartPath, "charts", "linked"))
	require.NoError(t, err)
	assert.True(t, linkInfo.Mode()&os.ModeSymlink != 0)
	target, err := os.Readlink(filepath.Join(chartPath, "charts", "linked"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("..", "linked"), target)

	loaded, err := loader.LoadDir(ctx, chartPath)
	require.NoError(t, err)
	require.NotNil(t, loaded.Lock)
	require.NoError(t, verifyGeneration(ctx, filepath.Join(chartPath, "charts"), filepath.Join(chartPath, "charts"), loaded.Metadata.Dependencies, loaded.Lock))

	require.NoError(t, m.Build(ctx))
	loaded, err = loader.LoadDir(ctx, chartPath)
	require.NoError(t, err)
	require.NoError(t, verifyGeneration(ctx, filepath.Join(chartPath, "charts"), filepath.Join(chartPath, "charts"), loaded.Metadata.Dependencies, loaded.Lock))
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))
}
