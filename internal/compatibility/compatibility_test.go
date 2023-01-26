package compatibility

import (
	"testing"

	"github.com/tj/assert"
)

func TestFilterNewerVersion(t *testing.T) {
	imageList := []string{
		"v0.0.0",
		"v1.0.0",
		"v1.0.1",
		"v1.0.2",
		"v1.1.0",
	}

	testCases := map[string]struct {
		images     []string
		version    string
		wantImages []string
	}{
		"filters <= v1.0.0": {
			images:  imageList,
			version: "v1.0.0",
			wantImages: []string{
				"v1.0.1",
				"v1.0.2",
				"v1.1.0",
			},
		},
		"no compatible images": {
			images:  imageList,
			version: "v999.999.999",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			compatibleImages := FilterNewerVersion(tc.version, tc.images)
			assert.EqualValues(tc.wantImages, compatibleImages)
		})
	}
}

func TestNextMinorVersion(t *testing.T) {
	testCases := map[string]struct {
		version              string
		wantNextMinorVersion string
		wantErr              bool
	}{
		"gets next": {
			version:              "v1.0.0",
			wantNextMinorVersion: "v1.1",
		},
		"gets next from minor version": {
			version:              "v1.0",
			wantNextMinorVersion: "v1.1",
		},
		"empty version": {
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			gotNext, err := NextMinorVersion(tc.version)
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.Equal(tc.wantNextMinorVersion, gotNext)
		})
	}
}

func TestCompatibleVersions(t *testing.T) {
	testCases := map[string]struct {
		a         string
		b         string
		wantError bool
	}{
		"success": {
			a: "v0.0.0",
			b: "v0.0.0",
		},
		"different major version": {
			a:         "v1",
			b:         "v2",
			wantError: true,
		},
		"major version diff too large": {
			a:         "v1.0",
			b:         "v1.2",
			wantError: true,
		},
		"b has to be the newer version": {
			a:         "v2.4.0",
			b:         "v2.4.0-pre.0.20230109121528-d24fac00f018",
			wantError: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			err := CompatibleVersions(tc.a, tc.b)
			if tc.wantError {
				assert.Error(err)
				return
			}
			assert.NoError(err)
		})
	}
}
