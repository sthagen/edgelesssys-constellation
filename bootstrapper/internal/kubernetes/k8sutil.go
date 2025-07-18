/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package kubernetes

import (
	"context"
	"log/slog"
	"net"

	"github.com/edgelesssys/constellation/v2/internal/versions/components"
)

type clusterUtil interface {
	InstallComponents(ctx context.Context, kubernetesComponents components.Components) error
	InitCluster(ctx context.Context, initConfig []byte, nodeName, clusterName string, ips []net.IP, conformanceMode bool, log *slog.Logger) ([]byte, error)
	JoinCluster(ctx context.Context, joinConfig []byte, log *slog.Logger) error
	StartKubelet() error
}
