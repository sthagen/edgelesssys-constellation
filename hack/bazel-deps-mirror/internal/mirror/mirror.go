/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// package mirror is used upload and download Bazel dependencies to and from a mirror.
package mirror

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Maintainer can upload and download files to and from a CAS mirror.
type Maintainer struct {
	objectStorageClient objectStorageClient
	uploadClient        uploadClient
	httpClient          httpClient
	// bucket is the name of the S3 bucket to use.
	bucket string
	// mirrorBaseURL is the base URL of the public CAS http endpoint.
	mirrorBaseURL string

	unauthenticated bool
	dryRun          bool

	log *slog.Logger
}

// NewUnauthenticated creates a new Maintainer that dose not require authentication can only download files from a CAS mirror.
func NewUnauthenticated(mirrorBaseURL string, dryRun bool, log *slog.Logger) *Maintainer {
	return &Maintainer{
		httpClient:      http.DefaultClient,
		mirrorBaseURL:   mirrorBaseURL,
		unauthenticated: true,
		dryRun:          dryRun,
		log:             log,
	}
}

// New creates a new Maintainer that can upload and download files to and from a CAS mirror.
func New(ctx context.Context, region, bucket, mirrorBaseURL string, dryRun bool, log *slog.Logger) (*Maintainer, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	s3C := s3.NewFromConfig(cfg)
	uploadC := s3manager.NewUploader(s3C)

	return &Maintainer{
		objectStorageClient: s3C,
		uploadClient:        uploadC,
		bucket:              bucket,
		mirrorBaseURL:       mirrorBaseURL,
		httpClient:          http.DefaultClient,
		dryRun:              dryRun,
		log:                 log,
	}, nil
}

// MirrorURL returns the public URL of a file in the CAS mirror.
func (m *Maintainer) MirrorURL(hash string) (string, error) {
	if _, err := hex.DecodeString(hash); err != nil {
		return "", fmt.Errorf("invalid hash %q: %w", hash, err)
	}
	key := path.Join(keyBase, hash)
	pubURL, err := url.Parse(m.mirrorBaseURL)
	if err != nil {
		return "", err
	}
	pubURL.Path = path.Join(pubURL.Path, key)
	return pubURL.String(), nil
}

// Mirror downloads a file from one of the existing (non-mirror) urls and uploads it to the CAS mirror.
// It also calculates the hash of the file during streaming and checks if it matches the expected hash.
func (m *Maintainer) Mirror(ctx context.Context, hash string, urls []string) error {
	if m.unauthenticated {
		return errors.New("cannot upload in unauthenticated mode")
	}

	for _, url := range urls {
		m.log.Debug(fmt.Sprintf("Mirroring file with hash %q from %q", hash, url))
		body, err := m.downloadFromUpstream(ctx, url)
		if err != nil {
			m.log.Debug(fmt.Sprintf("Failed to download file from %q: %q", url, err))
			continue
		}
		defer body.Close()
		streamedHash := sha256.New()
		tee := io.TeeReader(body, streamedHash)
		if err := m.put(ctx, hash, tee); err != nil {
			m.log.Warn(fmt.Sprintf("Failed to stream file from upstream %q to mirror: %v.. Trying next url.", url, err))
			continue
		}
		actualHash := hex.EncodeToString(streamedHash.Sum(nil))

		if actualHash != hash {
			return fmt.Errorf("hash mismatch while streaming file to mirror: expected %v, got %v", hash, actualHash)
		}
		pubURL, err := m.MirrorURL(hash)
		if err != nil {
			return err
		}
		m.log.Debug(fmt.Sprintf("File uploaded successfully to mirror from %q as %q", url, pubURL))
		return nil
	}
	return fmt.Errorf("failed to download / reupload file with hash %v from any of the urls: %v", hash, urls)
}

// Learn downloads a file from one of the existing (non-mirror) urls, hashes it and returns the hash.
func (m *Maintainer) Learn(ctx context.Context, urls []string) (string, error) {
	for _, url := range urls {
		m.log.Debug(fmt.Sprintf("Learning new hash from %q", url))
		body, err := m.downloadFromUpstream(ctx, url)
		if err != nil {
			m.log.Debug(fmt.Sprintf("Failed to download file from %q: %q", url, err))
			continue
		}
		defer body.Close()
		streamedHash := sha256.New()
		if _, err := io.Copy(streamedHash, body); err != nil {
			m.log.Debug(fmt.Sprintf("Failed to stream file from %q: %q", url, err))
		}
		learnedHash := hex.EncodeToString(streamedHash.Sum(nil))
		m.log.Debug(fmt.Sprintf("File successfully downloaded from %q with %q", url, learnedHash))
		return learnedHash, nil
	}
	return "", fmt.Errorf("failed to download file / learn hash from any of the urls: %v", urls)
}

// Check checks if a file is present and has the correct hash in the CAS mirror.
func (m *Maintainer) Check(ctx context.Context, expectedHash string) error {
	m.log.Debug(fmt.Sprintf("Checking consistency of object with hash %q", expectedHash))
	if m.unauthenticated {
		return m.checkUnauthenticated(ctx, expectedHash)
	}
	return m.checkAuthenticated(ctx, expectedHash)
}

// checkReadonly checks if a file is present and has the correct hash in the CAS mirror.
// It uses the authenticated CAS s3 endpoint to download the file metadata.
func (m *Maintainer) checkAuthenticated(ctx context.Context, expectedHash string) error {
	key := path.Join(keyBase, expectedHash)
	m.log.Debug(fmt.Sprintf("Check: s3 getObjectAttributes {Bucket: %q, Key: %q}", m.bucket, key))
	attributes, err := m.objectStorageClient.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
		Bucket:           &m.bucket,
		Key:              &key,
		ObjectAttributes: []s3types.ObjectAttributes{s3types.ObjectAttributesChecksum, s3types.ObjectAttributesObjectParts},
	})
	if err != nil {
		return err
	}

	hasChecksum := attributes.Checksum != nil && attributes.Checksum.ChecksumSHA256 != nil && len(*attributes.Checksum.ChecksumSHA256) > 0
	isSinglePart := attributes.ObjectParts == nil || attributes.ObjectParts.TotalPartsCount == nil || *attributes.ObjectParts.TotalPartsCount == 1

	if !hasChecksum || !isSinglePart {
		// checksums are not guaranteed to be present
		// and if present, they are only meaningful for single part objects
		// fallback if checksum cannot be verified from attributes
		m.log.Debug(fmt.Sprintf("S3 object attributes cannot be used to verify key %q. Falling back to download.", key))
		return m.checkUnauthenticated(ctx, expectedHash)
	}

	actualHash, err := base64.StdEncoding.DecodeString(*attributes.Checksum.ChecksumSHA256)
	if err != nil {
		return err
	}
	return compareHashes(expectedHash, actualHash)
}

// checkReadonly checks if a file is present and has the correct hash in the CAS mirror.
// It uses the public CAS http endpoint to download the file.
func (m *Maintainer) checkUnauthenticated(ctx context.Context, expectedHash string) error {
	pubURL, err := m.MirrorURL(expectedHash)
	if err != nil {
		return err
	}
	m.log.Debug(fmt.Sprintf("Check: http get {Url: %q}", pubURL))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pubURL, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %v", resp.StatusCode)
	}

	actualHash := sha256.New()
	if _, err := io.Copy(actualHash, resp.Body); err != nil {
		return err
	}
	return compareHashes(expectedHash, actualHash.Sum(nil))
}

// put uploads a file to the CAS mirror.
func (m *Maintainer) put(ctx context.Context, hash string, data io.Reader) error {
	if m.unauthenticated {
		return errors.New("cannot upload in unauthenticated mode")
	}

	key := path.Join(keyBase, hash)
	if m.dryRun {
		m.log.Debug(fmt.Sprintf("DryRun: s3 put object {Bucket: %q, Key: %q}", m.bucket, key))
		return nil
	}
	m.log.Debug(fmt.Sprintf("Uploading object with hash %q to \"s3://%s/%s\"", hash, m.bucket, key))
	_, err := m.uploadClient.Upload(ctx, &s3.PutObjectInput{
		Bucket:            &m.bucket,
		Key:               &key,
		Body:              data,
		ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
	})
	return err
}

// downloadFromUpstream downloads a file from one of the existing (non-mirror) urls.
func (m *Maintainer) downloadFromUpstream(ctx context.Context, url string) (body io.ReadCloser, retErr error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			resp.Body.Close()
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %v", resp.StatusCode)
	}
	return resp.Body, nil
}

func compareHashes(expectedHash string, actualHash []byte) error {
	if len(actualHash) != sha256.Size {
		return fmt.Errorf("actual hash should to be %v bytes, got %v", sha256.Size, len(actualHash))
	}
	if len(expectedHash) != hex.EncodedLen(sha256.Size) {
		return fmt.Errorf("expected hash should be %v bytes, got %v", hex.EncodedLen(sha256.Size), len(expectedHash))
	}
	actualHashStr := hex.EncodeToString(actualHash)
	if expectedHash != actualHashStr {
		return fmt.Errorf("expected hash %v, mirror returned %v", expectedHash, actualHashStr)
	}
	return nil
}

type objectStorageClient interface {
	GetObjectAttributes(ctx context.Context, params *s3.GetObjectAttributesInput, optFns ...func(*s3.Options)) (*s3.GetObjectAttributesOutput, error)
}

type uploadClient interface {
	Upload(ctx context.Context, input *s3.PutObjectInput, opts ...func(*s3manager.Uploader)) (*s3manager.UploadOutput, error)
}

type httpClient interface {
	Get(url string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
}

const (
	// DryRun is a flag to enable dry run mode.
	DryRun = true
	// Run is a flag to perform actual operations.
	Run     = false
	keyBase = "constellation/cas/sha256"
)
