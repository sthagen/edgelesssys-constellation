/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/edgelesssys/constellation/v2/cli/internal/cloudcmd"
	"github.com/edgelesssys/constellation/v2/cli/internal/helm"
	"github.com/edgelesssys/constellation/v2/internal/attestation/measurements"
	"github.com/edgelesssys/constellation/v2/internal/cloud/cloudprovider"
	"github.com/edgelesssys/constellation/v2/internal/config"
	"github.com/edgelesssys/constellation/v2/internal/constants"
	"github.com/edgelesssys/constellation/v2/internal/file"
	"github.com/edgelesssys/constellation/v2/internal/kubernetes/kubectl"
	consemver "github.com/edgelesssys/constellation/v2/internal/semver"
	"github.com/edgelesssys/constellation/v2/internal/sigstore"
	"github.com/edgelesssys/constellation/v2/internal/versions"
	"github.com/edgelesssys/constellation/v2/internal/versionsapi"
	"github.com/edgelesssys/constellation/v2/internal/versionsapi/fetcher"
	"github.com/siderolabs/talos/pkg/machinery/config/encoder"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func newUpgradeCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check for possible upgrades.",
		Long:  "Check which upgrades can be applied to your Constellation Cluster.",
		Args:  cobra.NoArgs,
		RunE:  runUpgradeCheck,
	}

	cmd.Flags().BoolP("write-config", "w", false, "Update the specified config file with the suggested versions")

	return cmd
}

func runUpgradeCheck(cmd *cobra.Command, args []string) error {
	log, err := newCLILogger(cmd)
	if err != nil {
		return fmt.Errorf("creating logger: %w", err)
	}
	defer log.Sync()
	fileHandler := file.NewHandler(afero.NewOsFs())
	flags, err := parseUpgradeCheckFlags(cmd)
	if err != nil {
		return err
	}
	checker, err := cloudcmd.NewUpgrader(cmd.OutOrStdout(), log)
	if err != nil {
		return err
	}
	versionListFetcher := fetcher.NewFetcher()
	rekor, err := sigstore.NewRekor()
	if err != nil {
		return fmt.Errorf("constructing Rekor client: %w", err)
	}
	cliVersion := getCurrentCLIVersion()
	up := &upgradeCheckCmd{log: log}

	return up.upgradeCheck(cmd, checker, versionListFetcher, fileHandler, http.DefaultClient, rekor, flags, cliVersion)
}

func parseUpgradeCheckFlags(cmd *cobra.Command) (upgradeCheckFlags, error) {
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return upgradeCheckFlags{}, err
	}
	writeConfig, err := cmd.Flags().GetBool("write-config")
	if err != nil {
		return upgradeCheckFlags{}, err
	}

	return upgradeCheckFlags{
		configPath:   configPath,
		writeConfig:  writeConfig,
		cosignPubKey: constants.CosignPublicKey,
	}, nil
}

type upgradeCheckCmd struct {
	log debugLog
}

// upgradePlan plans an upgrade of a Constellation cluster.
func (up *upgradeCheckCmd) upgradeCheck(cmd *cobra.Command, checker upgradeChecker, verListFetcher versionListFetcher,
	fileHandler file.Handler, client *http.Client, rekor rekorVerifier, flags upgradeCheckFlags,
	cliVersion string,
) error {
	conf, err := config.New(fileHandler, flags.configPath)
	if err != nil {
		return displayConfigValidationErrors(cmd.ErrOrStderr(), err)
	}
	up.log.Debugf("Read configuration from %q", flags.configPath)
	// get current image version of the cluster
	csp := conf.GetProvider()
	up.log.Debugf("Using provider %s", csp.String())

	currentServicesVersions, currentImageVersion, currentK8sVersion, err := up.collectCurrentVersions(cmd.Context(), checker)
	if err != nil {
		return err
	}

	supportedServicesVersions, supportedImageVersions, supportedK8sVersions, err := up.collectSupportedVersions(cmd, currentImageVersion, verListFetcher, fileHandler, client, rekor, flags, csp, cliVersion)
	if err != nil {
		return err
	}

	upgrade := versionUpgrade{
		supportedServicesVersions: supportedServicesVersions,
		supportedImageVersions:    supportedImageVersions,
		supportedK8sVersions:      supportedK8sVersions,
		currentServicesVersions:   currentServicesVersions,
		currentImageVersion:       currentImageVersion,
		currentK8sVersion:         currentK8sVersion,
	}

	updateMsg, err := upgrade.buildString()
	if err != nil {
		return err
	}

	// Get new CLI versions
	// TODO: Filter CLI versions for ones that are compatible with current K8s version. Needs versionsapi extension.
	next, err := consemver.NextMinorVersion(cliVersion)
	if err != nil {
		return fmt.Errorf("calculating nextMinorVersion: %w", err)
	}
	allowedVersions := []string{semver.MajorMinor(cliVersion), next}
	newCLIVersions, err := up.getNewerVersions(cmd.Context(), verListFetcher, cliVersion, allowedVersions)
	if err != nil {
		return err
	}

	// Print section
	if len(updateMsg) > 0 {
		fmt.Println("The following updates are available with this CLI:")
		fmt.Print(updateMsg)
		return nil
	}
	if len(newCLIVersions) > 0 {
		fmt.Printf("More versions are available with these CLI versions: %s\n", newCLIVersions)
		fmt.Println("Download at: https://github.com/edgelesssys/constellation/releases")
		return nil
	}

	fmt.Println("No further updates available.")

	return nil
}

func (up *upgradeCheckCmd) getNewerVersions(ctx context.Context, verListFetcher versionListFetcher, currentVersion string, allowedVersions []string) ([]string, error) {
	var updateCandidates []string
	for _, minorVer := range allowedVersions {
		patchList := versionsapi.List{
			Ref:         versionsapi.ReleaseRef,
			Stream:      "stable",
			Base:        minorVer,
			Granularity: versionsapi.GranularityMinor,
			Kind:        versionsapi.VersionKindImage,
		}
		patchList, err := verListFetcher.FetchVersionList(ctx, patchList)
		if err != nil {
			return nil, fmt.Errorf("fetching version list: %w", err)
		}
		updateCandidates = append(updateCandidates, patchList.Versions...)
	}
	up.log.Debugf("Update candidates are %v", updateCandidates)

	// filter for newer images only
	newerVersions := consemver.FilterNewerVersion(currentVersion, updateCandidates)
	up.log.Debugf("Of those versions, these ones are newer: %v", newerVersions)

	return newerVersions, nil
}

type versionUpgrade struct {
	supportedServicesVersions map[string]string
	supportedImageVersions    []string
	supportedK8sVersions      []string
	currentServicesVersions   map[string]string
	currentImageVersion       string
	currentK8sVersion         string
}

func (v *versionUpgrade) buildString() (string, error) {
	result := bytes.Buffer{}

	_, msg := printUpdate(v.currentK8sVersion, v.supportedK8sVersions)
	if len(msg) > 0 {
		fmt.Fprintf(&result, "  Kubernetes: %s --> ", v.currentK8sVersion)
		fmt.Fprint(&result, msg)
		fmt.Fprintln(&result, "")
	}

	_, msg = printUpdate(v.currentImageVersion, v.supportedImageVersions)
	if len(msg) > 0 {
		fmt.Fprintf(&result, "  Image: %s --> ", v.currentImageVersion)
		fmt.Fprint(&result, msg)
		fmt.Fprintln(&result, "")

	}

	if len(v.supportedServicesVersions) != len(v.currentServicesVersions) {
		return "", errors.New("mismatching service maps")
	}
	msgmsg := bytes.Buffer{}
	for k := range v.currentServicesVersions {
		_, msg = printUpdate(v.currentServicesVersions[k], []string{v.supportedServicesVersions[k]})
		if len(msg) > 0 {
			fmt.Fprintf(&msgmsg, "    %s: %s --> ", k, v.currentServicesVersions[k])
			fmt.Fprint(&msgmsg, msg)
			fmt.Fprintln(&msgmsg, "")
		}
	}
	if len(msgmsg.String()) > 0 {
		fmt.Fprintf(&result, "  Services:\n")
		fmt.Fprint(&result, msgmsg.String())
		fmt.Fprintln(&result, "")
	}

	return result.String(), nil
}

// printUpdate prints versions that are valid upgrades to the current version.
// It returns the upgrade with the smallest version jump or an empty string.
func printUpdate(currentVersion string, supportedVersions []string) (string, string) {
	if len(supportedVersions) == 0 {
		return "", ""
	}

	buf := bytes.Buffer{}
	selectedVersion := ""
	for i, version := range supportedVersions {
		validUpgrade, err := consemver.IsValidUpgrade(currentVersion, version)
		if err != nil {
			continue
		}

		if i > 0 {
			fmt.Fprint(&buf, " ")
		}

		if validUpgrade {
			fmt.Fprint(&buf, version)
			if selectedVersion == "" {
				selectedVersion = version
			}
		}
	}

	return selectedVersion, strings.TrimSpace(buf.String())
}

func (up *upgradeCheckCmd) collectCurrentVersions(ctx context.Context, checker upgradeChecker) (serviceVersions map[string]string, imageVersion string, k8sVersion string, err error) {
	helmClient, err := helm.NewClient(kubectl.New(), constants.AdminConfFilename, constants.HelmNamespace, up.log)
	if err != nil {
		return nil, "", "", fmt.Errorf("setting up helm client: %w", err)
	}

	serviceVersions, err = helmClient.Versions()
	if err != nil {
		return nil, "", "", fmt.Errorf("getting service versions: %w", err)
	}

	imageVersion, err = getCurrentImageVersion(ctx, checker)
	if err != nil {
		return nil, "", "", fmt.Errorf("getting image version: %w", err)
	}

	k8sVersion, err = getCurrentKubernetesVersion(ctx, checker)
	if err != nil {
		return nil, "", "", fmt.Errorf("getting image version: %w", err)
	}

	return serviceVersions, imageVersion, k8sVersion, nil
}

// getCurrentImageVersion retrieves the semantic version of the image currently installed in the cluster.
// If the cluster is not using a release image, an error is returned.
func getCurrentImageVersion(ctx context.Context, checker upgradeChecker) (string, error) {
	_, imageVersion, err := checker.GetCurrentImage(ctx)
	if err != nil {
		return "", err
	}

	if !semver.IsValid(imageVersion) {
		return "", fmt.Errorf("current image version is not a release image version: %q", imageVersion)
	}

	return imageVersion, nil
}

// getCurrentKubernetesVersion retrieves the semantic version of Kubernetes currently installed in the cluster.
func getCurrentKubernetesVersion(ctx context.Context, checker upgradeChecker) (string, error) {
	_, k8sVersion, err := checker.GetCurrentKubernetesVersion(ctx)
	if err != nil {
		return "", err
	}

	if !semver.IsValid(k8sVersion) {
		return "", fmt.Errorf("current kubernetes version is not a valid semver string: %q", k8sVersion)
	}

	return k8sVersion, nil
}

func getCurrentCLIVersion() string {
	return "v" + constants.VersionInfo
}

func (up *upgradeCheckCmd) collectSupportedVersions(cmd *cobra.Command, version string, verListFetcher versionListFetcher,
	fileHandler file.Handler, client *http.Client, rekor rekorVerifier, flags upgradeCheckFlags, csp cloudprovider.Provider,
	cliVersion string,
) (serviceVersions map[string]string, imageVersions []string, k8sVersions []string, err error) {
	k8sVersions = versions.SupportedK8sVersions()
	serviceVersions, err = helm.AvailableServiceVersions()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading service versions: %w", err)
	}
	imageVersions, err = up.fetchNewImages(cmd, version, verListFetcher, fileHandler, client, rekor, flags, csp, cliVersion)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading image versions: %w", err)
	}

	return serviceVersions, imageVersions, k8sVersions, nil
}

func (up *upgradeCheckCmd) fetchNewImages(cmd *cobra.Command, version string, verListFetcher versionListFetcher, fileHandler file.Handler, client *http.Client, rekor rekorVerifier, flags upgradeCheckFlags, csp cloudprovider.Provider, cliVersion string) ([]string, error) {
	// find compatible images
	// image updates should always be possible for the current minor version of the cluster
	// (e.g. 0.1.0 -> 0.1.1, 0.1.2, 0.1.3, etc.)
	// additionally, we allow updates to the next minor version (e.g. 0.1.0 -> 0.2.0)
	// if the CLI minor version is newer than the cluster minor version
	currentImageMinorVer := semver.MajorMinor(version)
	currentCLIMinorVer := semver.MajorMinor(cliVersion)
	nextImageMinorVer, err := consemver.NextMinorVersion(currentImageMinorVer)
	if err != nil {
		return nil, fmt.Errorf("calculating next image minor version: %w", err)
	}
	up.log.Debugf("Current image minor version is %s", currentImageMinorVer)
	up.log.Debugf("Current CLI minor version is %s", currentCLIMinorVer)
	up.log.Debugf("Next image minor version is %s", nextImageMinorVer)

	cliImageCompare := semver.Compare(currentCLIMinorVer, currentImageMinorVer)

	allowedMinorVersions := []string{currentImageMinorVer, nextImageMinorVer}
	switch {
	case cliImageCompare < 0:
		cmd.PrintErrln("Warning: CLI version is older than cluster image version. This is not supported.")
	case cliImageCompare == 0:
		allowedMinorVersions = []string{currentImageMinorVer}
	case cliImageCompare > 0:
		allowedMinorVersions = []string{currentImageMinorVer, nextImageMinorVer}
	}
	up.log.Debugf("Allowed minor versions are %#v", allowedMinorVersions)

	newerImages, err := up.getNewerVersions(cmd.Context(), verListFetcher, currentImageMinorVer, allowedMinorVersions)
	if err != nil {
		return nil, err
	}

	// get expected measurements for each image
	upgrades, err := getCompatibleImageMeasurements(cmd.Context(), cmd, client, rekor, []byte(flags.cosignPubKey), csp, newerImages)
	if err != nil {
		return nil, fmt.Errorf("fetching measurements for compatible images: %w", err)
	}
	up.log.Debugf("Compatible image measurements are %v", upgrades)

	if len(upgrades) == 0 {
		cmd.PrintErrln("No compatible images found to upgrade to.")
		return nil, nil
	}

	// write upgrade plan to stdout
	up.log.Debugf("Writing upgrade plan to stdout")
	content, err := encoder.NewEncoder(upgrades).Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding compatible images: %w", err)
	}
	_, err = cmd.OutOrStdout().Write(content)

	// write upgrade plan to file
	if flags.writeConfig {
		up.log.Debugf("Writing upgrade plan to file")
		fileHandler.WriteYAML("flags.filePath", upgrades)
	}
	return newerImages, nil
}

// getCompatibleImageMeasurements retrieves the expected measurements for each image.
func getCompatibleImageMeasurements(ctx context.Context, cmd *cobra.Command, client *http.Client, rekor rekorVerifier, pubK []byte,
	csp cloudprovider.Provider, images []string,
) (map[string]config.UpgradeConfig, error) {
	upgrades := make(map[string]config.UpgradeConfig)
	for _, img := range images {
		measurementsURL, err := measurementURL(csp, img, "measurements.json")
		if err != nil {
			return nil, err
		}

		signatureURL, err := measurementURL(csp, img, "measurements.json.sig")
		if err != nil {
			return nil, err
		}

		var fetchedMeasurements measurements.M
		hash, err := fetchedMeasurements.FetchAndVerify(
			ctx, client,
			measurementsURL,
			signatureURL,
			pubK,
			measurements.WithMetadata{
				CSP:   csp,
				Image: img,
			},
		)
		if err != nil {
			cmd.PrintErrf("Skipping image %q: %s\n", img, err)
			continue
		}

		if err = verifyWithRekor(ctx, rekor, hash); err != nil {
			cmd.PrintErrf("Warning: Unable to verify '%s' in Rekor.\n", hash)
			cmd.PrintErrf("Make sure measurements are correct.\n")
		}

		upgrades[img] = config.UpgradeConfig{
			Image:        img,
			Measurements: fetchedMeasurements,
			CSP:          csp,
		}

	}

	return upgrades, nil
}

type upgradeCheckFlags struct {
	configPath   string
	writeConfig  bool
	cosignPubKey string
}

type nopWriteCloser struct {
	io.Writer
}

func (c *nopWriteCloser) Close() error { return nil }

type upgradeChecker interface {
	GetCurrentImage(ctx context.Context) (*unstructured.Unstructured, string, error)
	GetCurrentKubernetesVersion(ctx context.Context) (*unstructured.Unstructured, string, error)
}

type versionListFetcher interface {
	FetchVersionList(ctx context.Context, list versionsapi.List) (versionsapi.List, error)
}
