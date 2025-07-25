//go:build cgo

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/edgelesssys/constellation/v2/hack/qemu-metadata-api/dhcp/dnsmasq"
	"github.com/edgelesssys/constellation/v2/hack/qemu-metadata-api/dhcp/virtwrapper"
	"github.com/edgelesssys/constellation/v2/hack/qemu-metadata-api/server"
	"github.com/edgelesssys/constellation/v2/internal/logger"
	"libvirt.org/go/libvirt"
)

func main() {
	bindPort := flag.String("port", "8080", "Port to bind to")
	targetNetwork := flag.String("network", "constellation-network", "Name of the network in libvirt")
	libvirtURI := flag.String("libvirt-uri", "qemu:///system", "URI of the libvirt connection")
	leasesFileName := flag.String("dnsmasq-leases", "", "Path to the dnsmasq leases file")
	initSecretHash := flag.String("initsecrethash", "", "brcypt hash of the init secret")
	flag.Parse()

	log := logger.NewJSONLogger(slog.LevelInfo)

	var leaseGetter server.LeaseGetter
	if *leasesFileName == "" {
		conn, err := libvirt.NewConnect(*libvirtURI)
		if err != nil {
			log.With(slog.Any("error", err)).Error("Failed to connect to libvirt")
			os.Exit(1)
		}
		defer conn.Close()
		leaseGetter = virtwrapper.New(conn, *targetNetwork)
	} else {
		log.Info("Using dnsmasq leases file")
		leaseGetter = dnsmasq.New(*leasesFileName)
	}

	serv := server.New(log, *targetNetwork, *initSecretHash, leaseGetter)
	if err := serv.ListenAndServe(*bindPort); err != nil {
		log.With(slog.Any("error", err)).Error("Failed to serve")
		os.Exit(1)
	}
}
