/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

/*
Package main parses command line flags and starts the s3proxy server.
*/
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/edgelesssys/constellation/v2/internal/logger"
	"github.com/edgelesssys/constellation/v2/s3proxy/internal/router"
)

const (
	// defaultPort is the default port to listen on.
	defaultPort = 4433
	// defaultIP is the default IP to listen on.
	defaultIP = "0.0.0.0"
	// defaultRegion is the default AWS region to use.
	defaultRegion = "eu-west-1"
	// defaultCertLocation is the default location of the TLS certificate.
	defaultCertLocation = "/etc/s3proxy/certs"
	// defaultLogLevel is the default log level.
	defaultLogLevel = 0
)

func main() {
	flags, err := parseFlags()
	if err != nil {
		panic(err)
	}

	logger := logger.NewJSONLogger(logger.VerbosityFromInt(flags.logLevel))

	if flags.forwardMultipartReqs {
		logger.Warn("configured to forward multipart uploads, this may leak data to AWS")
	}

	if err := runServer(flags, logger); err != nil {
		panic(err)
	}
}

func runServer(flags cmdFlags, log *slog.Logger) error {
	log.With(slog.String("ip", flags.ip), slog.Int("port", defaultPort), slog.String("region", flags.region)).Info("listening")

	router, err := router.New(flags.region, flags.kmsEndpoint, flags.forwardMultipartReqs, log)
	if err != nil {
		return fmt.Errorf("creating router: %w", err)
	}

	server := http.Server{
		Addr:    fmt.Sprintf("%s:%d", flags.ip, defaultPort),
		Handler: http.HandlerFunc(router.Serve),
		// Disable HTTP/2. Serving HTTP/2 will cause some clients to use HTTP/2.
		// It seems like AWS S3 does not support HTTP/2.
		// Having HTTP/2 enabled will at least cause the aws-sdk-go V1 copy-object operation to fail.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	// i.e. if TLS is enabled.
	if !flags.noTLS {
		cert, err := tls.LoadX509KeyPair(flags.certLocation+"/s3proxy.crt", flags.certLocation+"/s3proxy.key")
		if err != nil {
			return fmt.Errorf("loading TLS certificate: %w", err)
		}

		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// TLSConfig is populated, so we can safely pass empty strings to ListenAndServeTLS.
		return server.ListenAndServeTLS("", "")
	}

	log.Warn("TLS is disabled")
	return server.ListenAndServe()
}

func parseFlags() (cmdFlags, error) {
	noTLS := flag.Bool("no-tls", false, "disable TLS and listen on port 80, otherwise listen on 443")
	ip := flag.String("ip", defaultIP, "ip to listen on")
	region := flag.String("region", defaultRegion, "AWS region in which target bucket is located")
	certLocation := flag.String("cert", defaultCertLocation, "location of TLS certificate")
	kmsEndpoint := flag.String("kms", "key-service.kube-system:9000", "endpoint of the KMS service to get key encryption keys from")
	forwardMultipartReqs := flag.Bool("allow-multipart", false, "forward multipart requests to the target bucket; beware: this may store unencrypted data on AWS. See the documentation for more information")
	level := flag.Int("level", defaultLogLevel, "log level")

	flag.Parse()

	netIP := net.ParseIP(*ip)
	if netIP == nil {
		return cmdFlags{}, fmt.Errorf("not a valid IPv4 address: %s", *ip)
	}

	return cmdFlags{
		noTLS:                *noTLS,
		ip:                   netIP.String(),
		region:               *region,
		certLocation:         *certLocation,
		kmsEndpoint:          *kmsEndpoint,
		forwardMultipartReqs: *forwardMultipartReqs,
		logLevel:             *level,
	}, nil
}

type cmdFlags struct {
	noTLS                bool
	ip                   string
	region               string
	certLocation         string
	kmsEndpoint          string
	forwardMultipartReqs bool
	logLevel             int
}
