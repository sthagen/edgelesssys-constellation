package semver

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-version"
	"golang.org/x/mod/semver"
)

var (
	// ErrMajorMismatch signals that the major version of two compared versions don't match.
	ErrMajorMismatch = errors.New("missmatching major version")
	// ErrMinorDrift signals that the minor version of two compared versions are further apart than one.
	ErrMinorDrift = errors.New("minor versions more than 1 apart")
	// ErrSemVer signals that a given version does not adhere to the Semver syntax.
	ErrSemVer = errors.New("invalid semver")
)

// CompatibleVersions tests that version b is greater than a, but not further away than one minor version.
func CompatibleVersions(a, b string) error {
	versionA, err := version.NewSemver(a)
	if err != nil {
		return ErrSemVer
	}
	versionB, err := version.NewSemver(b)
	if err != nil {
		return ErrSemVer
	}

	// Major versions always have to match.
	if versionA.Segments()[0] != versionB.Segments()[0] {
		return ErrMajorMismatch
	}
	// If user only specified major version, we can stop comparing now.
	if len(versionA.Segments()) == 1 {
		return nil
	}

	if versionA.GreaterThan(versionB) {
		return ErrMinorDrift
	}
	// Abort if minor version drift between CLI and versionA value is greater than 1.
	if versionA.Segments()[1]-versionB.Segments()[1] < -1 {
		return ErrMinorDrift
	}

	return nil
}

// IsValidUpgrade checks that a and b adhere to a version drift of 1 and b is greater than a.
func IsValidUpgrade(a, b string) (bool, error) {
	err := CompatibleVersions(a, b)
	if err != nil {
		return false, err
	}

	return semver.Compare(a, b) == -1, nil
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
