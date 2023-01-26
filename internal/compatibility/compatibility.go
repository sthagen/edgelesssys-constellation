/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package compatibility offers helper functions for comparing and filtering versions.
*/
package compatibility

import (
	"errors"
	"fmt"

	"golang.org/x/mod/semver"
)

var (
	// ErrMajorMismatch signals that the major version of two compared versions don't match.
	ErrMajorMismatch = errors.New("missmatching major version")
	// ErrMinorDrift signals that the minor version of two compared versions are further apart than one.
	ErrMinorDrift = errors.New("target version needs to be equal or up to one minor version higher")
	// ErrSemVer signals that a given version does not adhere to the Semver syntax.
	ErrSemVer = errors.New("invalid semver")
)

// IsValidUpgrade checks that a and b adhere to a version drift of 1 and b is greater than a.
func IsValidUpgrade(a, b string) (bool, error) {
	err := CompatibleVersions(a, b)
	if err != nil {
		return false, fmt.Errorf("testing version compatibility (%s, %s): %w", a, b, err)
	}

	return semver.Compare(a, b) == -1, nil
}

// CompatibleVersions tests that version b is greater than a, but not further away than one minor version.
func CompatibleVersions(a, b string) error {
	if !semver.IsValid(a) || !semver.IsValid(b) {
		return ErrSemVer
	}
	aMajor, aMinor, _, err := parseCanonicalSemver(a)
	if err != nil {
		return err
	}
	bMajor, bMinor, _, err := parseCanonicalSemver(b)
	if err != nil {
		return err
	}

	// Major versions always have to match.
	if aMajor != bMajor {
		return ErrMajorMismatch
	}

	if semver.Compare(a, b) == 1 {
		return ErrMinorDrift
	}
	// Abort if minor version drift between CLI and versionA value is greater than 1.
	if aMinor-bMinor < -1 {
		return ErrMinorDrift
	}

	return nil
}

// FilterNewerVersion filters the list of versions to only include versions newer than currentVersion.
func FilterNewerVersion(currentVersion string, newVersions []string) []string {
	var result []string

	for _, image := range newVersions {
		// check if image is newer than current version
		if semver.Compare(image, currentVersion) <= 0 {
			continue
		}
		result = append(result, image)
	}
	return result
}

func NextMinorVersion(version string) (string, error) {
	major, minor, _, err := parseCanonicalSemver(version)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v%d.%d", major, minor+1), nil
}

func parseCanonicalSemver(version string) (major int, minor int, patch int, err error) {
	version = semver.Canonical(version) // ensure version is in canonical form (vX.Y.Z)
	num, err := fmt.Sscanf(version, "v%d.%d.%d", &major, &minor, &patch)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("parsing version: %w", err)
	}
	if num != 3 {
		return 0, 0, 0, fmt.Errorf("parsing version: expected 3 numbers, got %d", num)
	}

	return major, minor, patch, nil
}
