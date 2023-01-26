package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateVersionCompatibilityHelper checks that basic version and image short paths are correctly validated.
// The CLI version this test assumes is "v0.0.0" as defined in constants.go.
func TestValidateVersionCompatibilityHelper(t *testing.T) {
	testCases := map[string]struct {
		version   string
		wantError bool
	}{
		"full version works": {
			version: "v0.1.0",
		},
		"short path works": {
			version: "ref/main/stream/debug/v0.1.0-pre.0.20230109121528-d24fac00f018",
		},
		"minor version difference > 1": {
			version:   "ref/main/stream/debug/v0.2.0-pre.0.20230109121528-d24fac00f018",
			wantError: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			err := validateVersionCompatibilityHelper("Image", tc.version)
			if tc.wantError {
				assert.Error(err)
				return
			}
			assert.NoError(err)
		})
	}
}
