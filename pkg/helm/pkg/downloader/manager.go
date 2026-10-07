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
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	stdfs "io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"

	"github.com/werf/nelm/v2/pkg/helm/intern/resolver"
	"github.com/werf/nelm/v2/pkg/helm/intern/urlutil"
	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/loader"
	chartutil "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2/util"
	"github.com/werf/nelm/v2/pkg/helm/pkg/getter"
	"github.com/werf/nelm/v2/pkg/helm/pkg/helmpath"
	"github.com/werf/nelm/v2/pkg/helm/pkg/registry"
	"github.com/werf/nelm/v2/pkg/helm/pkg/repo/v1"
)

// ErrRepoNotFound indicates that chart repositories can't be found in local repo cache.
// The value of Repos is missing repos.
type ErrRepoNotFound struct {
	Repos []string
}

// Error implements the error interface.
func (e ErrRepoNotFound) Error() string {
	return "no repository definition for " + strings.Join(e.Repos, ", ")
}

// Manager handles the lifecycle of fetching, resolving, and storing dependencies.
type Manager struct {
	// Out is used to print warnings and notifications.
	Out io.Writer
	// ChartPath is the path to the unpacked base chart upon which this operates.
	ChartPath string
	// Verification indicates whether the chart should be verified.
	Verify VerificationStrategy
	// Debug is the global "--debug" flag
	Debug bool
	// Keyring is the key ring file.
	Keyring string
	// SkipUpdate indicates that the repository should not be updated first.
	SkipUpdate bool
	// Getter collection for the operation
	Getters          []getter.Provider
	RegistryClient   *registry.Client
	RepositoryConfig string
	RepositoryCache  string

	AllowMissingRepos bool

	// ContentCache is a location where a cache of charts can be stored
	ContentCache string
}

func (m *Manager) SetChartPath(path string) {
	m.ChartPath = path
}

// Build rebuilds a local charts directory from a lockfile.
//
// If the lockfile is not present, this will run a Manager.Update()
//
// If SkipUpdate is set, this will not update the repository.
func (m *Manager) Build(ctx context.Context) error {
	return m.withDependencyTxn(ctx, m.buildLocked)
}

// Update updates a local charts directory.
//
// It first reads the Chart.yaml file, and then attempts to
// negotiate versions based on that. It will download the versions
// from remote chart repositories unless SkipUpdate is true.
func (m *Manager) Update(ctx context.Context) error {
	return m.withDependencyLock(ctx, func(ctx context.Context, txn *dependencyTxn) error {
		c, err := m.loadChartDir(ctx)
		if err != nil {
			return err
		}
		if c.Metadata.Dependencies == nil {
			return nil
		}
		if err := txn.create(); err != nil {
			return err
		}
		return m.finishDependencyTxn(txn, m.updateLocked(ctx, txn, c))
	})
}

func (m *Manager) finishDependencyTxn(txn *dependencyTxn, runErr error) error {
	if runErr != nil && !txn.keepWorkspace {
		txn.cleanup()
	}
	if runErr == nil && !txn.keepWorkspace {
		txn.cleanup()
	}
	return runErr
}

func (m *Manager) buildLocked(ctx context.Context, txn *dependencyTxn) error {
	c, err := m.loadChartDir(ctx)
	if err != nil {
		return err
	}

	lock := c.Lock
	if lock == nil {
		return m.updateLocked(ctx, txn, c)
	}

	req := c.Metadata.Dependencies

	// If using apiVersion v1, calculate the hash before resolve repo names
	// because resolveRepoNames will change req if req uses repo alias
	// and Helm 2 calculate the digest from the original req
	// Fix for: https://github.com/helm/helm/issues/7619
	var v2Sum string
	if c.Metadata.APIVersion == chart.APIVersionV1 {
		v2Sum, err = resolver.HashV2Req(req)
		if err != nil {
			return errors.New("the lock file (requirements.lock) is out of sync with the dependencies file (requirements.yaml). Please update the dependencies")
		}
	}

	if repoNames, err := m.resolveRepoNames(req); err != nil {
		return err
	} else if m.AllowMissingRepos {
		if _, err := m.ensureMissingRepos(repoNames, req); err != nil {
			return fmt.Errorf("unable to ensure missing repos: %w", err)
		}
	}

	if sum, err := resolver.HashReq(req, lock.Dependencies); err != nil || sum != lock.Digest {
		// If lock digest differs and chart is apiVersion v1, it maybe because the lock was built
		// with Helm 2 and therefore should be checked with Helm v2 hash
		// Fix for: https://github.com/helm/helm/issues/7233
		if c.Metadata.APIVersion == chart.APIVersionV1 {
			log.Println("warning: a valid Helm v3 hash was not found. Checking against Helm v2 hash...")
			if v2Sum != lock.Digest {
				return errors.New("the lock file (requirements.lock) is out of sync with the dependencies file (requirements.yaml). Please update the dependencies")
			}
		} else {
			return errors.New("the lock file (Chart.lock) is out of sync with the dependencies file (Chart.yaml). Please update the dependencies with 'helm dependency update'")
		}
	}

	if !m.AllowMissingRepos {
		if err := m.hasAllRepos(lock.Dependencies); err != nil {
			return err
		}
	}

	if !m.SkipUpdate {
		if err := m.UpdateRepositories(ctx); err != nil {
			return err
		}
	}

	prepared, err := txn.prepareCandidate(ctx, lock.Dependencies)
	if err != nil {
		return err
	}

	// The lock digest may be a Helm v2 hash for apiVersion v1 charts, while
	// candidate verification always uses the v3 digest computed over the
	// current (alias-resolved) requirements and the prepared dependencies.
	preparedDigest, err := resolver.HashReq(req, prepared)
	if err != nil {
		return err
	}
	verifiedLock := &chart.Lock{
		Generated:    lock.Generated,
		Digest:       preparedDigest,
		Dependencies: prepared,
	}
	if err := verifyGeneration(ctx, txn.candidateChartsDir(), t.mainChartsDir(), req, verifiedLock); err != nil {
		return fmt.Errorf("candidate charts do not match %s: %w", dependencyLockFileName(c.Metadata.APIVersion), err)
	}

	return txn.commit(ctx, commitOptions{
		publishLock: false,
		lockName:    dependencyLockFileName(c.Metadata.APIVersion),
		digest:      preparedDigest,
		req:         req,
		lock:        verifiedLock,
	})
}

func (m *Manager) updateLocked(ctx context.Context, txn *dependencyTxn, c *chart.Chart) error {
	req := c.Metadata.Dependencies

	repoNames, err := m.resolveRepoNames(req)
	if err != nil {
		return err
	}

	repoNames, err = m.ensureMissingRepos(repoNames, req)
	if err != nil {
		return err
	}

	if !m.SkipUpdate {
		if err := m.UpdateRepositories(ctx); err != nil {
			return err
		}
	}

	lock, err := m.resolve(ctx, req, repoNames)
	if err != nil {
		return err
	}

	prepared, err := txn.prepareCandidate(ctx, lock.Dependencies)
	if err != nil {
		return err
	}
	lock.Dependencies = prepared

	newDigest, err := resolver.HashReq(req, prepared)
	if err != nil {
		return err
	}
	lock.Digest = newDigest

	if err := verifyGeneration(ctx, txn.candidateChartsDir(), t.mainChartsDir(), req, lock); err != nil {
		return fmt.Errorf("candidate charts do not match resolved dependencies: %w", err)
	}

	publishLock := shouldPublishLock(c.Lock, newDigest)
	if publishLock {
		if err := txn.stageCandidateLock(lock); err != nil {
			return err
		}
	}

	return txn.commit(ctx, commitOptions{
		publishLock: publishLock,
		lockName:    dependencyLockFileName(c.Metadata.APIVersion),
		digest:      newDigest,
		req:         req,
		lock:        lock,
	})
}

func (m *Manager) loadChartDir(ctx context.Context) (*chart.Chart, error) {
	if fi, err := os.Stat(m.ChartPath); err != nil {
		return nil, fmt.Errorf("could not find %s: %w", m.ChartPath, err)
	} else if !fi.IsDir() {
		return nil, errors.New("only unpacked charts can be updated")
	}
	return loader.LoadDir(ctx, m.ChartPath)
}

// resolve takes a list of dependencies and translates them into an exact version to download.
//
// This returns a lock file, which has all of the dependencies normalized to a specific version.
func (m *Manager) resolve(ctx context.Context, req []*chart.Dependency, repoNames map[string]string) (*chart.Lock, error) {
	res := resolver.New(m.ChartPath, m.RepositoryCache, m.RegistryClient)
	return res.Resolve(ctx, req, repoNames)
}

func parseOCIRef(chartRef string) (string, string, error) {
	refTagRegexp := regexp.MustCompile(`^(oci://[^:]+(:[0-9]{1,5})?[^:]+):(.*)$`)
	caps := refTagRegexp.FindStringSubmatch(chartRef)
	if len(caps) != 4 {
		return "", "", fmt.Errorf("improperly formatted oci chart reference: %s", chartRef)
	}
	chartRef = caps[1]
	tag := caps[3]

	return chartRef, tag, nil
}

// hasAllRepos ensures that all of the referenced deps are in the local repo cache.
func (m *Manager) hasAllRepos(deps []*chart.Dependency) error {
	rf, err := loadRepoConfig(m.RepositoryConfig)
	if err != nil {
		return err
	}
	repos := rf.Repositories

	// Verify that all repositories referenced in the deps are actually known
	// by Helm.
	missing := []string{}
Loop:
	for _, dd := range deps {
		// If repo is from local path or OCI, continue
		if strings.HasPrefix(dd.Repository, "file://") || registry.IsOCI(dd.Repository) {
			continue
		}

		if dd.Repository == "" {
			continue
		}
		for _, repo := range repos {
			if urlutil.Equal(repo.URL, strings.TrimSuffix(dd.Repository, "/")) {
				continue Loop
			}
		}
		missing = append(missing, dd.Repository)
	}
	if len(missing) > 0 {
		return ErrRepoNotFound{missing}
	}
	return nil
}

// ensureMissingRepos attempts to ensure the repository information for repos
// not managed by Helm is present. This takes in the repoNames Helm is configured
// to work with along with the chart dependencies. It will find the deps not
// in a known repo and attempt to ensure the data is present for steps like
// version resolution.
func (m *Manager) ensureMissingRepos(repoNames map[string]string, deps []*chart.Dependency) (map[string]string, error) {

	var ru []*repo.Entry

	for _, dd := range deps {

		// If the chart is in the local charts directory no repository needs
		// to be specified.
		if dd.Repository == "" {
			continue
		}

		// When the repoName for a dependency is known we can skip ensuring
		if _, ok := repoNames[dd.Name]; ok {
			continue
		}

		// The generated repository name, which will result in an index being
		// locally cached, has a name pattern of "helm-manager-" followed by a
		// sha256 of the repo name. This assumes end users will never create
		// repositories with these names pointing to other repositories. Using
		// this method of naming allows the existing repository pulling and
		// resolution code to do most of the work.
		rn, err := key(dd.Repository)
		if err != nil {
			return repoNames, err
		}
		rn = managerKeyPrefix + rn

		repoNames[dd.Name] = rn

		// Assuming the repository is generally available. For Helm managed
		// access controls the repository needs to be added through the user
		// managed system. This path will work for public charts, like those
		// supplied by Bitnami, but not for protected charts, like corp ones
		// behind a username and pass.
		ri := &repo.Entry{
			Name: rn,
			URL:  dd.Repository,
		}
		ru = append(ru, ri)
	}

	// Calls to UpdateRepositories (a public function) will only update
	// repositories configured by the user. Here we update repos found in
	// the dependencies that are not known to the user if update skipping
	// is not configured.
	if !m.SkipUpdate && len(ru) > 0 {
		fmt.Fprintln(m.Out, "Getting updates for unmanaged Helm repositories...")
		if err := m.parallelRepoUpdate(ru); err != nil {
			return repoNames, err
		}
	}

	return repoNames, nil
}

// resolveRepoNames returns the repo names of the referenced deps which can be used to fetch the cached index file
// and replaces aliased repository URLs into resolved URLs in dependencies.
func (m *Manager) resolveRepoNames(deps []*chart.Dependency) (map[string]string, error) {
	rf, err := loadRepoConfig(m.RepositoryConfig)
	if err != nil {
		if errors.Is(err, stdfs.ErrNotExist) {
			return make(map[string]string), nil
		}
		return nil, err
	}
	repos := rf.Repositories

	reposMap := make(map[string]string)

	// Verify that all repositories referenced in the deps are actually known
	// by Helm.
	missing := []string{}
	for _, dd := range deps {
		// Don't map the repository, we don't need to download chart from charts directory
		if dd.Repository == "" {
			continue
		}
		// if dep chart is from local path, verify the path is valid
		if strings.HasPrefix(dd.Repository, "file://") {
			if _, err := resolver.GetLocalPath(dd.Repository, m.ChartPath); err != nil {
				return nil, err
			}

			if m.Debug {
				fmt.Fprintf(m.Out, "Repository from local path: %s\n", dd.Repository)
			}
			reposMap[dd.Name] = dd.Repository
			continue
		}

		if registry.IsOCI(dd.Repository) {
			reposMap[dd.Name] = dd.Repository
			continue
		}

		found := false

		for _, repo := range repos {
			if (strings.HasPrefix(dd.Repository, "@") && strings.TrimPrefix(dd.Repository, "@") == repo.Name) ||
				(strings.HasPrefix(dd.Repository, "alias:") && strings.TrimPrefix(dd.Repository, "alias:") == repo.Name) {
				found = true
				dd.Repository = repo.URL
				reposMap[dd.Name] = repo.Name
				break
			} else if urlutil.Equal(repo.URL, dd.Repository) {
				found = true
				reposMap[dd.Name] = repo.Name
				break
			}
		}
		if !found {
			repository := dd.Repository
			// Add if URL
			_, err := url.ParseRequestURI(repository)
			if err == nil {
				reposMap[repository] = repository
				continue
			}
			missing = append(missing, repository)
		}
	}
	if len(missing) > 0 {
		errorMessage := fmt.Sprintf("no repository definition for %s. Please add them via 'helm repo add'", strings.Join(missing, ", "))
		// It is common for people to try to enter "stable" as a repository instead of the actual URL.
		// For this case, let's give them a suggestion.
		containsNonURL := false
		for _, repo := range missing {
			if !strings.Contains(repo, "//") && !strings.HasPrefix(repo, "@") && !strings.HasPrefix(repo, "alias:") {
				containsNonURL = true
			}
		}
		if containsNonURL {
			errorMessage += `
Note that repositories must be URLs or aliases. For example, to refer to the "example"
repository, use "https://charts.example.com/" or "@example" instead of
"example". Don't forget to add the repo, too ('helm repo add').`
		}
		return nil, errors.New(errorMessage)
	}
	return reposMap, nil
}

// UpdateRepositories updates all of the local repos to the latest.
func (m *Manager) UpdateRepositories(ctx context.Context) error {
	rf, err := loadRepoConfig(m.RepositoryConfig)
	if err != nil {
		return err
	}
	repos := rf.Repositories
	if len(repos) > 0 {
		fmt.Fprintln(m.Out, "Hang tight while we grab the latest from your chart repositories...")
		// This prints warnings straight to out.
		if err := m.parallelRepoUpdate(repos); err != nil {
			return err
		}
		fmt.Fprintln(m.Out, "Update Complete. ⎈Happy Helming!⎈")
	}
	return nil
}

// Filter out duplicate repos by URL, including those with trailing slashes.
func dedupeRepos(repos []*repo.Entry) []*repo.Entry {
	seen := make(map[string]*repo.Entry)
	for _, r := range repos {
		// Normalize URL by removing trailing slashes.
		seenURL := strings.TrimSuffix(r.URL, "/")
		seen[seenURL] = r
	}
	var unique []*repo.Entry
	for _, r := range seen {
		unique = append(unique, r)
	}
	return unique
}

func (m *Manager) parallelRepoUpdate(repos []*repo.Entry) error {

	var wg sync.WaitGroup

	localRepos := dedupeRepos(repos)

	for _, c := range localRepos {
		r, err := repo.NewChartRepository(c, m.Getters)
		if err != nil {
			return err
		}
		r.CachePath = m.RepositoryCache
		wg.Add(1)
		go func(r *repo.ChartRepository) {
			if _, err := r.DownloadIndexFile(); err != nil {
				// For those dependencies that are not known to helm and using a
				// generated key name we display the repo url.
				if strings.HasPrefix(r.Config.Name, managerKeyPrefix) {
					fmt.Fprintf(m.Out, "...Unable to get an update from the %q chart repository:\n\t%s\n", r.Config.URL, err)
				} else {
					fmt.Fprintf(m.Out, "...Unable to get an update from the %q chart repository (%s):\n\t%s\n", r.Config.Name, r.Config.URL, err)
				}
			} else {
				// For those dependencies that are not known to helm and using a
				// generated key name we display the repo url.
				if strings.HasPrefix(r.Config.Name, managerKeyPrefix) {
					fmt.Fprintf(m.Out, "...Successfully got an update from the %q chart repository\n", r.Config.URL)
				} else {
					fmt.Fprintf(m.Out, "...Successfully got an update from the %q chart repository\n", r.Config.Name)
				}
			}
			wg.Done()
		}(r)
	}
	wg.Wait()

	return nil
}

// findChartURL searches the cache of repo data for a chart that has the name and the repoURL specified.
//
// 'name' is the name of the chart. Version is an exact semver, or an empty string. If empty, the
// newest version will be returned.
//
// repoURL is the repository to search
//
// If it finds a URL that is "relative", it will prepend the repoURL.
func (m *Manager) findChartURL(name, version, repoURL string, repos map[string]*repo.ChartRepository) (url, username, password string, insecureSkipTLSVerify, passCredentialsAll bool, caFile, certFile, keyFile string, err error) {
	if registry.IsOCI(repoURL) {
		return fmt.Sprintf("%s/%s:%s", repoURL, name, version), "", "", false, false, "", "", "", nil
	}

	for _, cr := range repos {
		if urlutil.Equal(repoURL, cr.Config.URL) {
			var entry repo.ChartVersions
			entry, err = findEntryByName(name, cr)
			if err != nil {
				// TODO: Where linting is skipped in this function we should
				// refactor to remove naked returns while ensuring the same
				// behavior
				//nolint:nakedret
				return
			}
			var ve *repo.ChartVersion
			ve, err = findVersionedEntry(version, entry)
			if err != nil {
				//nolint:nakedret
				return
			}
			url, err = repo.ResolveReferenceURL(repoURL, ve.URLs[0])
			if err != nil {
				//nolint:nakedret
				return
			}
			username = cr.Config.Username
			password = cr.Config.Password
			passCredentialsAll = cr.Config.PassCredentialsAll
			insecureSkipTLSVerify = cr.Config.InsecureSkipTLSVerify
			caFile = cr.Config.CAFile
			certFile = cr.Config.CertFile
			keyFile = cr.Config.KeyFile
			//nolint:nakedret
			return
		}
	}
	url, err = repo.FindChartInRepoURL(repoURL, name, m.Getters, repo.WithChartVersion(version), repo.WithClientTLS(certFile, keyFile, caFile))
	if err == nil {
		return url, username, password, false, false, "", "", "", err
	}
	err = fmt.Errorf("chart %s not found in %s: %w", name, repoURL, err)
	return url, username, password, false, false, "", "", "", err
}

// findEntryByName finds an entry in the chart repository whose name matches the given name.
//
// It returns the ChartVersions for that entry.
func findEntryByName(name string, cr *repo.ChartRepository) (repo.ChartVersions, error) {
	for ename, entry := range cr.IndexFile.Entries {
		if ename == name {
			return entry, nil
		}
	}
	return nil, errors.New("entry not found")
}

// findVersionedEntry takes a ChartVersions list and returns a single chart version that satisfies the version constraints.
//
// If version is empty, the first chart found is returned.
func findVersionedEntry(version string, vers repo.ChartVersions) (*repo.ChartVersion, error) {
	for _, verEntry := range vers {
		if len(verEntry.URLs) == 0 {
			// Not a legit entry.
			continue
		}

		if version == "" || versionEquals(version, verEntry.Version) {
			return verEntry, nil
		}
	}
	return nil, errors.New("no matching version")
}

func versionEquals(v1, v2 string) bool {
	sv1, err := semver.NewVersion(v1)
	if err != nil {
		// Fallback to string comparison.
		return v1 == v2
	}
	sv2, err := semver.NewVersion(v2)
	if err != nil {
		return false
	}
	return sv1.Equal(sv2)
}

// loadChartRepositories reads the repositories.yaml, and then builds a map of
// ChartRepositories.
//
// The key is the local name (which is only present in the repositories.yaml).
func (m *Manager) loadChartRepositories() (map[string]*repo.ChartRepository, error) {
	indices := map[string]*repo.ChartRepository{}

	// Load repositories.yaml file
	rf, err := loadRepoConfig(m.RepositoryConfig)
	if err != nil {
		return indices, fmt.Errorf("failed to load %s: %w", m.RepositoryConfig, err)
	}

	for _, re := range rf.Repositories {
		lname := re.Name
		idxFile := filepath.Join(m.RepositoryCache, helmpath.CacheIndexFile(lname))
		index, err := repo.LoadIndexFile(idxFile)
		if err != nil {
			return indices, err
		}

		// TODO: use constructor
		cr := &repo.ChartRepository{
			Config:    re,
			IndexFile: index,
		}
		indices[lname] = cr
	}
	return indices, nil
}

// archive a dep chart from local directory and save it into destPath
func tarFromLocalDir(ctx context.Context, chartpath, name, repo, version, destPath string) (string, error) {
	if !strings.HasPrefix(repo, "file://") {
		return "", fmt.Errorf("wrong format: chart %s repository %s", name, repo)
	}

	origPath, err := resolver.GetLocalPath(repo, chartpath)
	if err != nil {
		return "", err
	}

	ch, err := loader.LoadDir(ctx, origPath)
	if err != nil {
		return "", err
	}

	constraint, err := semver.NewConstraint(version)
	if err != nil {
		return "", fmt.Errorf("dependency %s has an invalid version/constraint format: %w", name, err)
	}

	v, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return "", err
	}

	if constraint.Check(v) {
		_, err = chartutil.Save(ch, destPath)
		return ch.Metadata.Version, err
	}

	return "", fmt.Errorf("can't get a valid version for dependency %s", name)
}

// The prefix to use for cache keys created by the manager for repo names
const managerKeyPrefix = "helm-manager-"

// key is used to turn a name, such as a repository url, into a filesystem
// safe name that is unique for querying. To accomplish this a unique hash of
// the string is used.
func key(name string) (string, error) {
	in := strings.NewReader(name)
	hash := crypto.SHA256.New()
	if _, err := io.Copy(hash, in); err != nil {
		return "", nil
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
