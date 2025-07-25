/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sapi

import (
	"context"
	"fmt"

	"github.com/coreos/go-systemd/v22/dbus"
)

func startSystemdUnit(ctx context.Context, unit string) error {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("establishing systemd connection: %w", err)
	}

	startChan := make(chan string)
	if _, err := conn.StartUnitContext(ctx, unit, "replace", startChan); err != nil {
		return fmt.Errorf("starting systemd unit %q: %w", unit, err)
	}

	// Wait for the enable to finish and actually check if it was
	// successful or not.
	result := <-startChan

	switch result {
	case "done":
		return nil

	default:
		return fmt.Errorf("starting systemd unit %q failed: expected %v but received %v", unit, "done", result)
	}
}

func enableSystemdUnit(ctx context.Context, unitPath string) error {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("establishing systemd connection: %w", err)
	}

	if _, _, err := conn.EnableUnitFilesContext(ctx, []string{unitPath}, true, true); err != nil {
		return fmt.Errorf("enabling systemd unit %q: %w", unitPath, err)
	}
	return nil
}
