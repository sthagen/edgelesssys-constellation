/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/edgelesssys/constellation/v2/cli/internal/cloudcmd"
	"github.com/edgelesssys/constellation/v2/internal/compatibility"
	"github.com/edgelesssys/constellation/v2/internal/config"
	"github.com/edgelesssys/constellation/v2/internal/constants"
	"github.com/edgelesssys/constellation/v2/internal/constellation/helm"
	"github.com/edgelesssys/constellation/v2/internal/constellation/state"
	"github.com/edgelesssys/constellation/v2/internal/kms/uri"
	"github.com/spf13/cobra"
)

// runHelmApply handles installing or upgrading helm charts for the cluster.
func (a *applyCmd) runHelmApply(cmd *cobra.Command, conf *config.Config, stateFile *state.State, upgradeDir string,
) error {
	a.log.Debug("Installing or upgrading Helm charts")
	var masterSecret uri.MasterSecret
	if err := a.fileHandler.ReadJSON(constants.MasterSecretFilename, &masterSecret); err != nil {
		return fmt.Errorf("reading master secret: %w", err)
	}

	options := helm.Options{
		CSP:                 conf.GetProvider(),
		AttestationVariant:  conf.GetAttestationConfig().GetVariant(),
		K8sVersion:          conf.KubernetesVersion,
		MicroserviceVersion: conf.MicroserviceVersion,
		DeployCSIDriver:     conf.DeployCSIDriver(),
		Force:               a.flags.force,
		Conformance:         a.flags.conformance,
		HelmWaitMode:        a.flags.helmWaitMode,
		ApplyTimeout:        a.flags.helmTimeout,
		AllowDestructive:    helm.DenyDestructive,
		ServiceCIDR:         conf.ServiceCIDR,
	}
	if conf.Provider.OpenStack != nil {
		var deployYawolLoadBalancer bool
		if conf.Provider.OpenStack.DeployYawolLoadBalancer != nil {
			deployYawolLoadBalancer = *conf.Provider.OpenStack.DeployYawolLoadBalancer
		}
		options.OpenStackValues = &helm.OpenStackValues{
			DeployYawolLoadBalancer: deployYawolLoadBalancer,
			FloatingIPPoolID:        conf.Provider.OpenStack.FloatingIPPoolID,
			YawolFlavorID:           conf.Provider.OpenStack.YawolFlavorID,
			YawolImageID:            conf.Provider.OpenStack.YawolImageID,
		}
	}

	a.log.Debug("Getting service account URI")
	serviceAccURI, err := cloudcmd.GetMarshaledServiceAccountURI(conf, a.fileHandler)
	if err != nil {
		return err
	}

	a.log.Debug("Preparing Helm charts")
	executor, includesUpgrades, err := a.applier.PrepareHelmCharts(options, stateFile, serviceAccURI, masterSecret)
	if errors.Is(err, helm.ErrConfirmationMissing) {
		if !a.flags.yes {
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
		options.AllowDestructive = helm.AllowDestructive
		executor, includesUpgrades, err = a.applier.PrepareHelmCharts(options, stateFile, serviceAccURI, masterSecret)
	}
	var upgradeErr *compatibility.InvalidUpgradeError
	if err != nil {
		if !errors.As(err, &upgradeErr) {
			return fmt.Errorf("preparing Helm charts: %w", err)
		}
		cmd.PrintErrln(err)
	}

	a.log.Debug("Backing up Helm charts")
	if err := a.backupHelmCharts(cmd.Context(), executor, includesUpgrades, upgradeDir); err != nil {
		return err
	}

	a.log.Debug("Applying Helm charts")
	if !a.flags.skipPhases.contains(skipInitPhase) {
		a.spinner.Start("Installing Kubernetes components ", false)
	} else {
		a.spinner.Start("Upgrading Kubernetes components ", false)
	}

	if err := executor.Apply(cmd.Context()); err != nil {
		return fmt.Errorf("applying Helm charts: %w", err)
	}
	a.spinner.Stop()

	if a.flags.skipPhases.contains(skipInitPhase) {
		cmd.Println("Successfully upgraded Constellation services.")
	}

	return nil
}

// backupHelmCharts saves the Helm charts for the upgrade to disk and creates a backup of existing CRDs and CRs.
func (a *applyCmd) backupHelmCharts(
	ctx context.Context, executor helm.Applier, includesUpgrades bool, upgradeDir string,
) error {
	// Save the Helm charts for the upgrade to disk
	chartDir := filepath.Join(upgradeDir, "helm-charts")
	if err := executor.SaveCharts(chartDir, a.fileHandler); err != nil {
		return fmt.Errorf("saving Helm charts to disk: %w", err)
	}
	a.log.Debug(fmt.Sprintf("Helm charts saved to %q", a.flags.pathPrefixer.PrefixPrintablePath(chartDir)))

	if includesUpgrades {
		a.log.Debug("Creating backup of CRDs and CRs")
		crds, err := a.applier.BackupCRDs(ctx, a.fileHandler, upgradeDir)
		if err != nil {
			return fmt.Errorf("creating CRD backup: %w", err)
		}
		if err := a.applier.BackupCRs(ctx, a.fileHandler, crds, upgradeDir); err != nil {
			return fmt.Errorf("creating CR backup: %w", err)
		}
	}

	return nil
}
