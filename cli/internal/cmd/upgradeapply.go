/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/edgelesssys/constellation/v2/cli/internal/clusterid"
	"github.com/edgelesssys/constellation/v2/cli/internal/helm"
	"github.com/edgelesssys/constellation/v2/cli/internal/image"
	"github.com/edgelesssys/constellation/v2/cli/internal/kubernetes"
	"github.com/edgelesssys/constellation/v2/cli/internal/terraform"
	"github.com/edgelesssys/constellation/v2/internal/cloud/cloudprovider"
	"github.com/edgelesssys/constellation/v2/internal/compatibility"
	"github.com/edgelesssys/constellation/v2/internal/config"
	"github.com/edgelesssys/constellation/v2/internal/constants"
	"github.com/edgelesssys/constellation/v2/internal/file"
	"github.com/edgelesssys/constellation/v2/internal/variant"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
)

func newUpgradeApplyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply an upgrade to a Constellation cluster",
		Long:  "Apply an upgrade to a Constellation cluster by applying the chosen configuration.",
		Args:  cobra.NoArgs,
		RunE:  runUpgradeApply,
	}

	cmd.Flags().BoolP("yes", "y", false, "run upgrades without further confirmation\n"+
		"WARNING: might delete your resources in case you are using cert-manager in your cluster. Please read the docs.\n"+
		"WARNING: might unintentionally overwrite measurements in the running cluster.")
	cmd.Flags().Duration("timeout", 3*time.Minute, "change helm upgrade timeout\n"+
		"Might be useful for slow connections or big clusters.")
	if err := cmd.Flags().MarkHidden("timeout"); err != nil {
		panic(err)
	}

	return cmd
}

func runUpgradeApply(cmd *cobra.Command, _ []string) error {
	log, err := newCLILogger(cmd)
	if err != nil {
		return fmt.Errorf("creating logger: %w", err)
	}
	defer log.Sync()

	fileHandler := file.NewHandler(afero.NewOsFs())
	upgrader, err := kubernetes.NewUpgrader(cmd.Context(), cmd.OutOrStdout(), log)
	if err != nil {
		return err
	}

	fetcher := image.New()

	applyCmd := upgradeApplyCmd{upgrader: upgrader, log: log, fetcher: fetcher}
	return applyCmd.upgradeApply(cmd, fileHandler)
}

type upgradeApplyCmd struct {
	upgrader cloudUpgrader
	fetcher  imageFetcher
	log      debugLog
}

func (u *upgradeApplyCmd) upgradeApply(cmd *cobra.Command, fileHandler file.Handler) error {
	flags, err := parseUpgradeApplyFlags(cmd)
	if err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}
	conf, err := config.New(fileHandler, flags.configPath, flags.force)
	var configValidationErr *config.ValidationError
	if errors.As(err, &configValidationErr) {
		cmd.PrintErrln(configValidationErr.LongMessage())
	}
	if err != nil {
		return err
	}

	var idFile clusterid.File
	if err := fileHandler.ReadJSON(constants.ClusterIDsFileName, &idFile); err != nil {
		return fmt.Errorf("reading cluster ID file: %w", err)
	}
	conf.UpdateMAAURL(idFile.AttestationURL)

	// If an image upgrade was just executed there won't be a diff. The function will return nil in that case.
	if err := u.upgradeAttestConfigIfDiff(cmd, conf.GetAttestationConfig(), flags); err != nil {
		return fmt.Errorf("upgrading measurements: %w", err)
	}

	if err := u.migrateTerraform(cmd, fileHandler, u.fetcher, conf, flags); err != nil {
		return fmt.Errorf("performing Terraform migrations: %w", err)
	}

	if conf.GetProvider() == cloudprovider.Azure || conf.GetProvider() == cloudprovider.GCP {
		err = u.handleServiceUpgrade(cmd, conf, flags)
		upgradeErr := &compatibility.InvalidUpgradeError{}
		switch {
		case errors.As(err, &upgradeErr):
			cmd.PrintErrln(err)
		case err != nil:
			return fmt.Errorf("upgrading services: %w", err)
		}

		err = u.upgrader.UpgradeNodeVersion(cmd.Context(), conf)
		switch {
		case errors.Is(err, kubernetes.ErrInProgress):
			cmd.PrintErrln("Skipping image and Kubernetes upgrades. Another upgrade is in progress.")
		case errors.As(err, &upgradeErr):
			cmd.PrintErrln(err)
		case err != nil:
			return fmt.Errorf("upgrading NodeVersion: %w", err)
		}
	} else {
		cmd.PrintErrln("WARNING: Skipping service and image upgrades, which are currently only supported for Azure and GCP.")
	}

	return nil
}

// migrateTerraform checks if the Constellation version the cluster is being upgraded to requires a migration
// of cloud resources with Terraform. If so, the migration is performed.
func (u *upgradeApplyCmd) migrateTerraform(cmd *cobra.Command, file file.Handler, fetcher imageFetcher, conf *config.Config, flags upgradeApplyFlags) error {
	u.log.Debugf("Planning Terraform migrations")

	targets, vars, err := u.parseUpgradeVars(cmd, conf, fetcher)
	if err != nil {
		return fmt.Errorf("parsing upgrade variables: %w", err)
	}
	u.log.Debugf("Using migration targets:\n%v", targets)
	u.log.Debugf("Using Terraform variables:\n%v", vars)

	opts := kubernetes.TerraformUpgradeOptions{
		LogLevel:   flags.terraformLogLevel,
		CSP:        conf.GetProvider(),
		Vars:       vars,
		Targets:    targets,
		OutputFile: constants.TerraformMigrationOutputFile,
	}

	// Check if there are any Terraform migrations to apply
	hasDiff, err := u.upgrader.PlanTerraformMigrations(cmd.Context(), opts)
	if err != nil {
		return fmt.Errorf("planning Terraform migrations: %w", err)
	}

	if hasDiff {
		// If there are any Terraform migrations to apply, ask for confirmation
		if !flags.yes {
			ok, err := askToConfirm(cmd, "Do you want to apply the Terraform migrations?")
			if err != nil {
				return fmt.Errorf("asking for confirmation: %w", err)
			}
			if !ok {
				cmd.Println("Aborting upgrade.")
				return fmt.Errorf("aborted by user")
			}
		}
		u.log.Debugf("Applying Terraform migrations")
		err := u.upgrader.ApplyTerraformMigrations(cmd.Context(), file, opts)
		if err != nil {
			return fmt.Errorf("applying Terraform migrations: %w", err)
		}
		cmd.Printf("Terraform migrations applied successfully and output written to: %s\n", opts.OutputFile)
	} else {
		u.log.Debugf("No Terraform diff detected")
	}

	return nil
}

func (u *upgradeApplyCmd) parseUpgradeVars(cmd *cobra.Command, conf *config.Config, fetcher imageFetcher) ([]string, terraform.Variables, error) {
	// Fetch variables to execute Terraform script with
	imageRef, err := fetcher.FetchReference(cmd.Context(), conf)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching image reference: %w", err)
	}

	commonVariables := terraform.CommonVariables{
		Name:            conf.Name,
		StateDiskSizeGB: conf.StateDiskSizeGB,
		// Ignore node count as their values are only being respected for creation
		// See here: https://developer.hashicorp.com/terraform/language/meta-arguments/lifecycle#ignore_changes
	}

	switch conf.GetProvider() {
	case cloudprovider.AWS:
		targets := []string{}

		vars := &terraform.AWSClusterVariables{
			CommonVariables:        commonVariables,
			StateDiskType:          conf.Provider.AWS.StateDiskType,
			Region:                 conf.Provider.AWS.Region,
			Zone:                   conf.Provider.AWS.Zone,
			InstanceType:           conf.Provider.AWS.InstanceType,
			AMIImageID:             imageRef,
			IAMProfileControlPlane: conf.Provider.AWS.IAMProfileControlPlane,
			IAMProfileWorkerNodes:  conf.Provider.AWS.IAMProfileWorkerNodes,
			Debug:                  conf.IsDebugCluster(),
		}
		return targets, vars, nil
	case cloudprovider.Azure:
		targets := []string{"azurerm_attestation_provider.attestation_provider"}

		// Azure Terraform provider is very strict about it's casing
		imageRef = strings.Replace(imageRef, "CommunityGalleries", "communityGalleries", 1)
		imageRef = strings.Replace(imageRef, "Images", "images", 1)
		imageRef = strings.Replace(imageRef, "Versions", "versions", 1)

		vars := &terraform.AzureClusterVariables{
			CommonVariables:      commonVariables,
			Location:             conf.Provider.Azure.Location,
			ResourceGroup:        conf.Provider.Azure.ResourceGroup,
			UserAssignedIdentity: conf.Provider.Azure.UserAssignedIdentity,
			InstanceType:         conf.Provider.Azure.InstanceType,
			StateDiskType:        conf.Provider.Azure.StateDiskType,
			ImageID:              imageRef,
			SecureBoot:           *conf.Provider.Azure.SecureBoot,
			CreateMAA:            conf.GetAttestationConfig().GetVariant().Equal(variant.AzureSEVSNP{}),
			Debug:                conf.IsDebugCluster(),
		}
		return targets, vars, nil
	case cloudprovider.GCP:
		targets := []string{}

		vars := &terraform.GCPClusterVariables{
			CommonVariables: commonVariables,
			Project:         conf.Provider.GCP.Project,
			Region:          conf.Provider.GCP.Region,
			Zone:            conf.Provider.GCP.Zone,
			CredentialsFile: conf.Provider.GCP.ServiceAccountKeyPath,
			InstanceType:    conf.Provider.GCP.InstanceType,
			StateDiskType:   conf.Provider.GCP.StateDiskType,
			ImageID:         imageRef,
			Debug:           conf.IsDebugCluster(),
		}
		return targets, vars, nil
	default:
		return nil, nil, fmt.Errorf("unsupported provider: %s", conf.GetProvider())
	}
}

type imageFetcher interface {
	FetchReference(ctx context.Context, conf *config.Config) (string, error)
}

// upgradeAttestConfigIfDiff checks if the locally configured measurements are different from the cluster's measurements.
// If so the function will ask the user to confirm (if --yes is not set) and upgrade the measurements only.
func (u *upgradeApplyCmd) upgradeAttestConfigIfDiff(cmd *cobra.Command, newConfig config.AttestationCfg, flags upgradeApplyFlags) error {
	clusterAttestationConfig, _, err := u.upgrader.GetClusterAttestationConfig(cmd.Context(), newConfig.GetVariant())
	// Config migration from v2.7 to v2.8 requires us to skip comparing configs if the cluster is still using the legacy config.
	// TODO: v2.9 Remove error type check and always run comparison.
	if err != nil && !errors.Is(err, kubernetes.ErrLegacyJoinConfig) {
		return fmt.Errorf("getting cluster measurements: %w", err)
	}
	if err == nil {
		// If the current config is equal, or there is an error when comparing the configs, we skip the upgrade.
		if equal, err := newConfig.EqualTo(clusterAttestationConfig); err != nil || equal {
			return err
		}
	}

	if !flags.yes {
		ok, err := askToConfirm(cmd, "You are about to change your cluster's attestation config. Are you sure you want to continue?")
		if err != nil {
			return fmt.Errorf("asking for confirmation: %w", err)
		}
		if !ok {
			cmd.Println("Skipping upgrade.")
			return nil
		}
	}
	if err := u.upgrader.UpdateAttestationConfig(cmd.Context(), newConfig); err != nil {
		return fmt.Errorf("updating attestation config: %w", err)
	}
	return nil
}

func (u *upgradeApplyCmd) handleServiceUpgrade(cmd *cobra.Command, conf *config.Config, flags upgradeApplyFlags) error {
	err := u.upgrader.UpgradeHelmServices(cmd.Context(), conf, flags.upgradeTimeout, helm.DenyDestructive)
	if errors.Is(err, helm.ErrConfirmationMissing) {
		if !flags.yes {
			cmd.PrintErrln("WARNING: Upgrading cert-manager will destroy all custom resources you have manually created that are based on the current version of cert-manager.")
			ok, askErr := askToConfirm(cmd, "Do you want to upgrade cert-manager anyway?")
			if askErr != nil {
				return fmt.Errorf("asking for confirmation: %w", err)
			}
			if !ok {
				cmd.Println("Skipping upgrade.")
				return nil
			}
		}
		err = u.upgrader.UpgradeHelmServices(cmd.Context(), conf, flags.upgradeTimeout, helm.AllowDestructive)
	}

	return err
}

func parseUpgradeApplyFlags(cmd *cobra.Command) (upgradeApplyFlags, error) {
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return upgradeApplyFlags{}, err
	}

	yes, err := cmd.Flags().GetBool("yes")
	if err != nil {
		return upgradeApplyFlags{}, err
	}

	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		return upgradeApplyFlags{}, err
	}

	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return upgradeApplyFlags{}, fmt.Errorf("parsing force argument: %w", err)
	}

	logLevelString, err := cmd.Flags().GetString("tf-log")
	if err != nil {
		return upgradeApplyFlags{}, fmt.Errorf("parsing tf-log string: %w", err)
	}
	logLevel, err := terraform.ParseLogLevel(logLevelString)
	if err != nil {
		return upgradeApplyFlags{}, fmt.Errorf("parsing Terraform log level %s: %w", logLevelString, err)
	}

	return upgradeApplyFlags{
		configPath:        configPath,
		yes:               yes,
		upgradeTimeout:    timeout,
		force:             force,
		terraformLogLevel: logLevel,
	}, nil
}

type upgradeApplyFlags struct {
	configPath        string
	yes               bool
	upgradeTimeout    time.Duration
	force             bool
	terraformLogLevel terraform.LogLevel
}

type cloudUpgrader interface {
	UpgradeNodeVersion(ctx context.Context, conf *config.Config) error
	UpgradeHelmServices(ctx context.Context, config *config.Config, timeout time.Duration, allowDestructive bool) error
	UpdateAttestationConfig(ctx context.Context, newConfig config.AttestationCfg) error
	GetClusterAttestationConfig(ctx context.Context, variant variant.Variant) (config.AttestationCfg, *corev1.ConfigMap, error)
	PlanTerraformMigrations(ctx context.Context, opts kubernetes.TerraformUpgradeOptions) (bool, error)
	ApplyTerraformMigrations(ctx context.Context, file file.Handler, opts kubernetes.TerraformUpgradeOptions) error
}
