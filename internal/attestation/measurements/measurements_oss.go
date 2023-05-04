//go:build !enterprise

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package measurements

import (
	"github.com/edgelesssys/constellation/v2/internal/variant"
)

// DefaultsFor provides the default measurements for given cloud provider.
func DefaultsFor(attestationVariant variant.Variant) M {
	switch attestationVariant {
	case variant.AWSNitroTPM{}:
		return M{
			4:                         PlaceHolderMeasurement(PCRMeasurementLength),
			8:                         WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			9:                         PlaceHolderMeasurement(PCRMeasurementLength),
			11:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			12:                        PlaceHolderMeasurement(PCRMeasurementLength),
			13:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			uint32(PCRIndexClusterID): WithAllBytes(0x00, Enforce, PCRMeasurementLength),
		}
	case variant.AzureSEVSNP{}:
		return M{
			4:                         PlaceHolderMeasurement(PCRMeasurementLength),
			8:                         WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			9:                         PlaceHolderMeasurement(PCRMeasurementLength),
			11:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			12:                        PlaceHolderMeasurement(PCRMeasurementLength),
			13:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			uint32(PCRIndexClusterID): WithAllBytes(0x00, Enforce, PCRMeasurementLength),
		}
	case variant.AzureTrustedLaunch{}:
		return M{
			4:                         PlaceHolderMeasurement(PCRMeasurementLength),
			8:                         WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			9:                         PlaceHolderMeasurement(PCRMeasurementLength),
			11:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			12:                        PlaceHolderMeasurement(PCRMeasurementLength),
			13:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			uint32(PCRIndexClusterID): WithAllBytes(0x00, Enforce, PCRMeasurementLength),
		}
	case variant.GCPSEVES{}:
		return M{
			4:                         PlaceHolderMeasurement(PCRMeasurementLength),
			8:                         WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			9:                         PlaceHolderMeasurement(PCRMeasurementLength),
			11:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			12:                        PlaceHolderMeasurement(PCRMeasurementLength),
			13:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			uint32(PCRIndexClusterID): WithAllBytes(0x00, Enforce, PCRMeasurementLength),
		}
	case variant.QEMUTDX{}:
		return M{
			0:                         PlaceHolderMeasurement(TDXMeasurementLength),
			1:                         PlaceHolderMeasurement(TDXMeasurementLength),
			2:                         PlaceHolderMeasurement(TDXMeasurementLength),
			uint32(TDXIndexClusterID): WithAllBytes(0x00, Enforce, TDXMeasurementLength),
			4:                         PlaceHolderMeasurement(TDXMeasurementLength),
		}
	case variant.QEMUVTPM{}:
		return M{
			4:                         PlaceHolderMeasurement(PCRMeasurementLength),
			8:                         WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			9:                         PlaceHolderMeasurement(PCRMeasurementLength),
			11:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			12:                        PlaceHolderMeasurement(PCRMeasurementLength),
			13:                        WithAllBytes(0x00, Enforce, PCRMeasurementLength),
			uint32(PCRIndexClusterID): WithAllBytes(0x00, Enforce, PCRMeasurementLength),
		}
	default:
		return nil
	}
}
