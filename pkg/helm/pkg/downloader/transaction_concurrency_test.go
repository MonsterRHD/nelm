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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/werf/nelm/v2/pkg/helm/intern/resolver"
	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/loader"
)

const flockedTestTimeout = 300 * time.Millisecond

type flockHolder struct {
	t *testing.T
	f *flock.Flock
}

func newFlockHolder(t *testing.T, path string) *flockHolder {
	t.Helper()
	f := flock.New(path)
	require.NoError(t, f.Lock())
	h := &flockHolder{t: t, f: f}
	t.Cleanup(func() {
		if f.Locked() {
			_ = f.Unlock()
		}
	})
	return h
}

func (h *flockHolder) unlock() {
	require.NoError(h.t, h.f.Unlock())
}


func TestConcurrentBuildAndUpdate(t *testing.T) {
	ctx := context.Background()
	chartPath := newFileDependencyChart(t, chart.APIVersionV2)
	cache := tempRepoCache(t)

	first := &Manager{
		Out:              io.Discard,
		RepositoryConfig: repoConfig,
		RepositoryCache:  cache,
		ChartPath:        chartPath,
		SkipUpdate:       true,
	}
	require.NoError(t, first.Update(ctx))

	const workers = 8
	startBarrier := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			m := &Manager{
				Out:              new(bytes.Buffer),
				RepositoryConfig: repoConfig,
				RepositoryCache:  cache,
				ChartPath:        chartPath,
				SkipUpdate:       true,
			}
			<-startBarrier
			if i%2 == 0 {
				errs <- m.Build(ctx)
			} else {
				errs <- m.Update(ctx)
			}
		}(i)
	}
	close(startBarrier)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))

	loaded, err := loader.LoadDir(ctx, chartPath)
	require.NoError(t, err)
	require.NotNil(t, loaded.Lock)
	expectedDigest, err := resolver.HashReq(loaded.Metadata.Dependencies, loaded.Lock.Dependencies)
	require.NoError(t, err)
	assert.Equal(t, expectedDigest, loaded.Lock.Digest)
	require.NoError(t, verifyGeneration(ctx, filepath.Join(chartPath, "charts"), loaded.Metadata.Dependencies, loaded.Lock))
}

func TestSerializedOperationsObserveLatestGeneration(t *testing.T) {
	ctx := context.Background()
	chartPath := newFileDependencyChart(t, chart.APIVersionV2)
	cache := tempRepoCache(t)

	m := &Manager{
		Out:              io.Discard,
		RepositoryConfig: repoConfig,
		RepositoryCache:  cache,
		ChartPath:        chartPath,
		SkipUpdate:       true,
	}
	require.NoError(t, m.Update(ctx))

	absChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)
	lockPath, err := m.dependencyLockPath(absChartPath)
	require.NoError(t, err)
	holder := newFlockHolder(t, lockPath)

	blocked := &Manager{
		Out:              io.Discard,
		RepositoryConfig: repoConfig,
		RepositoryCache:  cache,
		ChartPath:        chartPath,
		SkipUpdate:       true,
	}
	blockedCtx, cancel := context.WithTimeout(ctx, flockedTestTimeout)
	defer cancel()
	err = blocked.Update(blockedCtx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acquire dependency lock")
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath), "blocked operation must not create any workspace state")

	holder.unlock()

	require.NoError(t, m.Update(ctx))
	assert.Empty(t, listTmpWorkspaceEntries(t, chartPath))

	loaded, err := loader.LoadDir(ctx, chartPath)
	require.NoError(t, err)
	require.NotNil(t, loaded.Lock)
	require.NoError(t, verifyGeneration(ctx, filepath.Join(chartPath, "charts"), loaded.Metadata.Dependencies, loaded.Lock))
}
