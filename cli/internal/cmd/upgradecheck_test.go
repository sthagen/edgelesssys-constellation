/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/edgelesssys/constellation/v2/internal/cloud/cloudprovider"
	"github.com/edgelesssys/constellation/v2/internal/config"
	"github.com/edgelesssys/constellation/v2/internal/constants"
	"github.com/edgelesssys/constellation/v2/internal/file"
	"github.com/edgelesssys/constellation/v2/internal/logger"
	"github.com/edgelesssys/constellation/v2/internal/versionsapi"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestBuildString checks that the resulting user output is as expected. Slow part is the Sscanf in parseCanonicalSemver().
func TestBuildString(t *testing.T) {
	testCases := map[string]struct {
		upgrade   versionUpgrade
		expected  string
		wantError bool
	}{
		"update everything": {
			upgrade: versionUpgrade{
				supportedServicesVersions: map[string]string{
					"constellation-services":  "v2.5.0",
					"constellation-operators": "v2.5.0",
				},
				supportedImageVersions: []string{"v2.3.0", "v2.4.0", "v2.5.0"},
				supportedK8sVersions:   []string{"v1.24.5", "v1.24.12", "v1.25.6"},
				currentServicesVersions: map[string]string{
					"constellation-services":  "v2.4.0",
					"constellation-operators": "v2.4.0",
				},
				currentImageVersion: "v2.4.0",
				currentK8sVersion:   "v1.24.5",
				newCLIVersions:      []string{"v2.5.0", "v2.6.0"},
			},
			expected: "The following updates are available with this CLI:\n  Kubernetes: v1.24.5 --> v1.24.12 v1.25.6\n  Image: v2.4.0 --> v2.5.0\n  Services:\n    constellation-operators: v2.4.0 --> v2.5.0\n    constellation-services: v2.4.0 --> v2.5.0\n",
		},
		"new cli": {
			upgrade: versionUpgrade{
				supportedServicesVersions: map[string]string{
					"constellation-services":  "v2.5.0",
					"constellation-operators": "v2.5.0",
				},
				supportedImageVersions: []string{"v2.3.0", "v2.4.0", "v2.5.0"},
				supportedK8sVersions:   []string{"v1.24.5", "v1.24.12", "v1.25.6"},
				currentServicesVersions: map[string]string{
					"constellation-services":  "v2.5.0",
					"constellation-operators": "v2.5.0",
				},
				currentImageVersion: "v2.5.0",
				currentK8sVersion:   "v1.25.6",
				newCLIVersions:      []string{"v2.6.0"},
			},
			expected: "More versions are available with these CLI versions: v2.6.0\nDownload at: https://github.com/edgelesssys/constellation/releases\n",
		},
		"no upgrades": {
			upgrade: versionUpgrade{
				supportedServicesVersions: map[string]string{
					"constellation-services":  "v2.5.0",
					"constellation-operators": "v2.5.0",
				},
				supportedImageVersions: []string{"v2.3.0", "v2.4.0", "v2.5.0"},
				supportedK8sVersions:   []string{"v1.24.5", "v1.24.12", "v1.25.6"},
				currentServicesVersions: map[string]string{
					"constellation-services":  "v2.5.0",
					"constellation-operators": "v2.5.0",
				},
				currentImageVersion: "v2.5.0",
				currentK8sVersion:   "v1.25.6",
				newCLIVersions:      []string{},
			},
			expected: "No further updates available.\n",
		},
		"no upgrades #2": {
			upgrade:  versionUpgrade{},
			expected: "No further updates available.\n",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			result, err := tc.upgrade.buildString()
			if tc.wantError {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.expected, result)
		})
	}
}

func TestGetCurrentImageVersion(t *testing.T) {
	testCases := map[string]struct {
		stubUpgradeChecker stubUpgradeChecker
		wantErr            bool
	}{
		"valid version": {
			stubUpgradeChecker: stubUpgradeChecker{
				image: "v1.0.0",
			},
		},
		"invalid version": {
			stubUpgradeChecker: stubUpgradeChecker{
				image: "invalid",
			},
			wantErr: true,
		},
		"GetCurrentImage error": {
			stubUpgradeChecker: stubUpgradeChecker{
				err: errors.New("error"),
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			version, err := getCurrentImageVersion(context.Background(), tc.stubUpgradeChecker)
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.True(semver.IsValid(version))
		})
	}
}

func TestGetCompatibleImageMeasurements(t *testing.T) {
	assert := assert.New(t)

	csp := cloudprovider.Azure
	images := []string{"v0.0.0", "v1.0.0"}

	client := newTestClient(func(req *http.Request) *http.Response {
		if strings.HasSuffix(req.URL.String(), "v0.0.0/azure/measurements.json") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"csp":"azure","image":"v0.0.0","measurements":{"0":{"expected":"0000000000000000000000000000000000000000000000000000000000000000","warnOnly":false}}}`)),
				Header:     make(http.Header),
			}
		}
		if strings.HasSuffix(req.URL.String(), "v0.0.0/azure/measurements.json.sig") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("MEQCIGRR7RaSMs892Ta06/Tz7LqPUxI05X4wQcP+nFFmZtmaAiBNl9X8mUKmUBfxg13LQBfmmpw6JwYQor5hOwM3NFVPAg==")),
				Header:     make(http.Header),
			}
		}

		if strings.HasSuffix(req.URL.String(), "v1.0.0/azure/measurements.json") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"csp":"azure","image":"v1.0.0","measurements":{"0":{"expected":"0000000000000000000000000000000000000000000000000000000000000000","warnOnly":false}}}`)),
				Header:     make(http.Header),
			}
		}
		if strings.HasSuffix(req.URL.String(), "v1.0.0/azure/measurements.json.sig") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("MEQCIFh8CVELp/Da2U2Jt404OXsUeDfqtrf3pqGRuvxnxhI8AiBTHF9tHEPwFedYG3Jgn2ELOxss+Ybc6135vEtClBrbpg==")),
				Header:     make(http.Header),
			}
		}

		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("Not found.")),
			Header:     make(http.Header),
		}
	})

	pubK := []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu78QgxOOcao6U91CSzEXxrKhvFTt\nJHNy+eX6EMePtDm8CnDF9HSwnTlD0itGJ/XHPQA5YX10fJAqI1y+ehlFMw==\n-----END PUBLIC KEY-----")

	upgrades, err := getCompatibleImageMeasurements(context.Background(), &cobra.Command{}, client, singleUUIDVerifier(), pubK, csp, images)
	assert.NoError(err)

	for _, image := range upgrades {
		assert.NotEmpty(image.Measurements)
	}
}

func TestUpgradePlan(t *testing.T) {
	testCases := map[string]struct {
		collector  stubVersionCollector
		flags      upgradeCheckFlags
		csp        cloudprovider.Provider
		cliVersion string
		wantError  bool
	}{
		"upgrades gcp": {
			collector: stubVersionCollector{
				supportedServicesVersions: map[string]string{
					"constellation-services":  "v2.5.0",
					"constellation-operators": "v2.5.0",
				},
				supportedImageVersions: []string{"v2.3.0", "v2.4.0", "v2.5.0"},
				supportedK8sVersions:   []string{"v1.24.5", "v1.24.12", "v1.25.6"},
				currentServicesVersions: map[string]string{
					"constellation-services":  "v2.4.0",
					"constellation-operators": "v2.4.0",
				},
				currentImageVersion: "v2.4.0",
				currentK8sVersion:   "v1.24.5",
				images:              []string{"v2.5.0"},
				newCLIVersions:      []string{"v2.5.0", "v2.6.0"},
			},
			flags: upgradeCheckFlags{
				configPath: constants.ConfigFilename,
			},
			csp:        cloudprovider.GCP,
			cliVersion: "v1.0.0",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			fileHandler := file.NewHandler(afero.NewMemMapFs())
			cfg := defaultConfigWithExpectedMeasurements(t, config.Default(), tc.csp)
			require.NoError(fileHandler.WriteYAML(tc.flags.configPath, cfg))

			checkCmd := upgradeCheckCmd{
				collect: &tc.collector,
				log:     logger.NewTest(t),
			}

			cmd := newUpgradeCheckCmd()

			err := checkCmd.upgradeCheck(cmd, fileHandler, tc.flags, tc.cliVersion)
			if tc.wantError {
				assert.Error(err)
				return
			}
			assert.NoError(err)
		})
	}
}

type stubVersionCollector struct {
	supportedServicesVersions map[string]string
	supportedImageVersions    []string
	supportedK8sVersions      []string
	currentServicesVersions   map[string]string
	currentImageVersion       string
	currentK8sVersion         string
	images                    []string
	newCLIVersions            []string
	someErr                   error
}

func (s *stubVersionCollector) currentVersions(ctx context.Context, log debugLog) (serviceVersions map[string]string, imageVersion string, k8sVersion string, err error) {
	return s.currentServicesVersions, s.currentImageVersion, s.currentK8sVersion, s.someErr
}

func (s *stubVersionCollector) supportedVersions(cmd *cobra.Command, version string, csp cloudprovider.Provider, log debugLog) (serviceVersions map[string]string, imageVersions []string, k8sVersions []string, err error) {
	return s.supportedServicesVersions, s.supportedImageVersions, s.supportedK8sVersions, s.someErr
}

func (s *stubVersionCollector) newImages(cmd *cobra.Command, version string, csp cloudprovider.Provider, log debugLog) ([]string, error) {
	return s.images, nil
}

func (s *stubVersionCollector) newerVersions(ctx context.Context, currentVersion string, allowedVersions []string, log debugLog) ([]string, error) {
	return s.newCLIVersions, nil
}

type stubUpgradeChecker struct {
	image      string
	k8sVersion string
	err        error
}

func (u stubUpgradeChecker) GetCurrentImage(context.Context) (*unstructured.Unstructured, string, error) {
	return nil, u.image, u.err
}

func (u stubUpgradeChecker) GetCurrentKubernetesVersion(ctx context.Context) (*unstructured.Unstructured, string, error) {
	return nil, u.k8sVersion, u.err
}

type stubVersionListFetcher struct {
	list versionsapi.List
	err  error
}

func (s stubVersionListFetcher) FetchVersionList(context.Context, versionsapi.List) (versionsapi.List, error) {
	return s.list, s.err
}
