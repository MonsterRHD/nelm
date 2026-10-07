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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/werf/nelm/v2/pkg/helm/intern/resolver"
	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	chartutil "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/util"
)

type verifyFixture struct {
	chartsDir string
	req       []*chart.Dependency
	lock      *chart.Lock
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	chartsDir := filepath.Join(t.TempDir(), "charts")
	require.NoError(t, os.MkdirAll(chartsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(chartsDir, "local-subchart-0.1.0.tgz"), readTestFile(t, "testdata/local-subchart-0.1.0.tgz"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(chartsDir, "signtest-0.1.0.tgz"), readTestFile(t, "testdata/signtest-0.1.0.tgz"), 0o644))
	require.NoError(t, chartutil.SaveDir(&chart.Chart{
		Metadata: &chart.Metadata{Name: "localno", Version: "0.1.0", APIVersion: chart.APIVersionV2},
	}, chartsDir))

	req := []*chart.Dependency{
		{Name: "local-subchart", Version: ">=0.1.0", Repository: "https://example.com/charts"},
		{Name: "signtest", Version: ">=0.1.0", Repository: "file://./signtest"},
		{Name: "localno", Version: ">=0.1.0"},
	}
	locked := []*chart.Dependency{
		{Name: "local-subchart", Version: "0.1.0", Repository: "https://example.com/charts"},
		{Name: "signtest", Version: "0.1.0", Repository: "file://./signtest"},
		{Name: "localno", Version: "0.1.0"},
	}
	digest, err := resolver.HashReq(req, locked)
	require.NoError(t, err)

	return &verifyFixture{
		chartsDir: chartsDir,
		req:       req,
		lock:      &chart.Lock{Generated: time.Unix(0, 0).UTC(), Digest: digest, Dependencies: locked},
	}
}

func TestVerifyGenerationValid(t *testing.T) {
	f := newVerifyFixture(t)
	require.NoError(t, verifyGeneration(context.Background(), f.chartsDir, f.chartsDir, f.req, f.lock))
}

func TestVerifyGenerationFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("missing archive", func(t *testing.T) {
		f := newVerifyFixture(t)
		require.NoError(t, os.Remove(filepath.Join(f.chartsDir, "signtest-0.1.0.tgz")))
		err := verifyGeneration(ctx, f.chartsDir, f.chartsDir, f.req, f.lock)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dependency signtest archive")
	})

	t.Run("archive contains wrong chart name", func(t *testing.T) {
		f := newVerifyFixture(t)
		require.NoError(t, os.Remove(filepath.Join(f.chartsDir, "signtest-0.1.0.tgz")))
		require.NoError(t, os.WriteFile(filepath.Join(f.chartsDir, "signtest-0.1.0.tgz"), readTestFile(t, "testdata/local-subchart-0.1.0.tgz"), 0o644))
		err := verifyGeneration(ctx, f.chartsDir, f.chartsDir, f.req, f.lock)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `contains chart "local-subchart"`)
	})

	t.Run("archive contains wrong version", func(t *testing.T) {
		chartsDir := filepath.Join(t.TempDir(), "charts")
		require.NoError(t, os.MkdirAll(chartsDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(chartsDir, "signtest-1.2.3.tgz"), readTestFile(t, "testdata/signtest-0.1.0.tgz"), 0o644))
		req := []*chart.Dependency{{Name: "signtest", Version: "1.2.3", Repository: "file://./signtest"}}
		locked := []*chart.Dependency{{Name: "signtest", Version: "1.2.3", Repository: "file://./signtest"}}
		digest, err := resolver.HashReq(req, locked)
		require.NoError(t, err)
		lock := &chart.Lock{Digest: digest, Dependencies: locked}
		err = verifyGeneration(ctx, chartsDir, chartsDir, req, lock)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `contains chart version "0.1.0", expected "1.2.3"`)
	})

	t.Run("unexpected extra archive", func(t *testing.T) {
		f := newVerifyFixture(t)
		require.NoError(t, os.WriteFile(filepath.Join(f.chartsDir, "signtest-0.2.0.tgz"), readTestFile(t, "testdata/signtest-0.1.0.tgz"), 0o644))
		err := verifyGeneration(ctx, f.chartsDir, f.chartsDir, f.req, f.lock)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected chart archive")
	})

	t.Run("digest mismatch", func(t *testing.T) {
		f := newVerifyFixture(t)
		f.lock.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		err := verifyGeneration(ctx, f.chartsDir, f.chartsDir, f.req, f.lock)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dependency lock digest")
	})

	t.Run("local dependency constraint unsatisfied", func(t *testing.T) {
		f := newVerifyFixture(t)
		f.lock.Dependencies[2].Version = ">=1.0.0"
		err := verifyGeneration(ctx, f.chartsDir, f.chartsDir, nil, f.lock)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not satisfy the constraint >=1.0.0")
	})

	t.Run("archive is a symbolic link", func(t *testing.T) {
		f := newVerifyFixture(t)
		archive := filepath.Join(f.chartsDir, "signtest-0.1.0.tgz")
		require.NoError(t, os.Remove(archive))
		require.NoError(t, os.Symlink(filepath.Join("..", "signtest-0.1.0.tgz"), archive))
		err := verifyGeneration(ctx, f.chartsDir, f.chartsDir, f.req, f.lock)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is a symbolic link")
	})

	t.Run("foreign non-loadable entry ignored", func(t *testing.T) {
		f := newVerifyFixture(t)
		require.NoError(t, os.WriteFile(filepath.Join(f.chartsDir, "signtest-0.1.0.tgz.prov"), readTestFile(t, "testdata/signtest-0.1.0.tgz.prov"), 0o644))
		assert.NoError(t, verifyGeneration(ctx, f.chartsDir, f.chartsDir, f.req, f.lock))
	})
}

func TestDependencyLockFileName(t *testing.T) {
	assert.Equal(t, "requirements.lock", dependencyLockFileName(chart.APIVersionV1))
	assert.Equal(t, "Chart.lock", dependencyLockFileName(chart.APIVersionV2))
}

func TestStageCandidateLock(t *testing.T) {
	chartPath := t.TempDir()
	m := newTestManager(t, chartPath)
	txn := newTxnWithWorkspace(t, m, chartPath)

	lock := &chart.Lock{
		Generated: time.Date(2025, 7, 4, 0, 0, 0, 0, time.UTC),
		Digest:    "sha256:12345",
		Dependencies: []*chart.Dependency{{
			Name:       "fantastic-chart",
			Version:    "1.2.3",
			Repository: "https://example.com/charts",
		}},
	}
	require.NoError(t, txn.stageCandidateLock(lock))

	expected, err := yaml.Marshal(lock)
	require.NoError(t, err)
	data, err := os.ReadFile(txn.candidateLockPath())
	require.NoError(t, err)
	assert.Equal(t, expected, data)

	err = txn.stageCandidateLock(lock)
	assert.Error(t, err)
}

func TestShouldPublishLock(t *testing.T) {
	assert.True(t, shouldPublishLock(nil, "sha256:abc"))
	assert.True(t, shouldPublishLock(&chart.Lock{Digest: "sha256:old"}, "sha256:new"))
	assert.False(t, shouldPublishLock(&chart.Lock{Digest: "sha256:same"}, "sha256:same"))
}

func TestCloneDependenciesIsolation(t *testing.T) {
	deps := []*chart.Dependency{{Name: "signtest", Version: "0.1.0", Repository: "file://./signtest"}}
	cloned := cloneDependencies(deps)
	cloned[0].Version = "9.9.9"
	assert.Equal(t, "0.1.0", deps[0].Version)
}
