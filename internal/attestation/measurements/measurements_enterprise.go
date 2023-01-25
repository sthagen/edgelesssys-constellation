//go:build enterprise

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package measurements

import "github.com/edgelesssys/constellation/v2/internal/cloud/cloudprovider"

// Regenerate the measurements by running go generate.
// The enterprise build tag is required to validate the measurements using production
// sigstore certificates.
//go:generate go run -tags enterprise measurement-generator/generate.go

// DefaultsFor provides the default measurements for given cloud provider.
func DefaultsFor(provider cloudprovider.Provider) M {
	switch provider {
	case cloudprovider.AWS:
		return M{
			0: {
				Expected: [32]byte{
					0x73, 0x7f, 0x76, 0x7a, 0x12, 0xf5, 0x4e, 0x70,
					0xee, 0xcb, 0xc8, 0x68, 0x40, 0x11, 0x32, 0x3a,
					0xe2, 0xfe, 0x2d, 0xd9, 0xf9, 0x07, 0x85, 0x57,
					0x79, 0x69, 0xd7, 0xa2, 0x01, 0x3e, 0x8c, 0x12,
				},
				WarnOnly: true,
			},
			2: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			3: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			4: {
				Expected: [32]byte{
					0xc9, 0x58, 0x08, 0xe9, 0xfe, 0x5c, 0x20, 0x80,
					0xea, 0x03, 0x29, 0x7f, 0x07, 0x46, 0x35, 0x2f,
					0x9e, 0xc8, 0xb3, 0x4a, 0x5d, 0x72, 0xe2, 0xba,
					0xf8, 0x34, 0x89, 0x88, 0x05, 0xc0, 0x2e, 0x5a,
				},
				WarnOnly: false,
			},
			5: {
				Expected: [32]byte{
					0xac, 0x99, 0xbc, 0x41, 0x68, 0x6e, 0x90, 0xef,
					0xeb, 0xbd, 0x13, 0x85, 0xc8, 0x27, 0xc0, 0x5e,
					0x6a, 0x4c, 0x9f, 0x50, 0x3a, 0xb6, 0xa3, 0x27,
					0xe4, 0xe0, 0x3d, 0x6a, 0xb3, 0x1a, 0x20, 0xc6,
				},
				WarnOnly: true,
			},
			6: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			7: {
				Expected: [32]byte{
					0x12, 0x0e, 0x49, 0x8d, 0xb2, 0xa2, 0x24, 0xbd,
					0x51, 0x2b, 0x6e, 0xfc, 0x9b, 0x02, 0x34, 0xf8,
					0x43, 0xe1, 0x0b, 0xf0, 0x61, 0xeb, 0x7a, 0x76,
					0xec, 0xca, 0x55, 0x09, 0xa2, 0x23, 0x89, 0x01,
				},
				WarnOnly: true,
			},
			8: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			9: {
				Expected: [32]byte{
					0x1a, 0x5e, 0x67, 0xa5, 0xe6, 0x1e, 0x97, 0xf0,
					0xa8, 0x58, 0xee, 0x8b, 0x87, 0x1b, 0xc2, 0x25,
					0x83, 0x9e, 0x75, 0xa4, 0x35, 0x36, 0x75, 0xab,
					0x01, 0xfa, 0x56, 0xd5, 0x1e, 0x75, 0xd0, 0xfa,
				},
				WarnOnly: false,
			},
			11: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			12: {
				Expected: [32]byte{
					0x52, 0x58, 0xe2, 0xcd, 0x12, 0xbc, 0xdf, 0xb9,
					0xc6, 0x01, 0x16, 0x88, 0x10, 0x39, 0x3e, 0x1c,
					0xbd, 0x2d, 0x0f, 0xda, 0x67, 0x19, 0x38, 0x47,
					0x56, 0x5b, 0x10, 0x61, 0x53, 0x5a, 0xf4, 0xc5,
				},
				WarnOnly: false,
			},
			13: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			14: {
				Expected: [32]byte{
					0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22,
					0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9,
					0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c,
					0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f,
				},
				WarnOnly: true,
			},
			15: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
		}
	case cloudprovider.Azure:
		return M{
			1: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			2: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			3: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			4: {
				Expected: [32]byte{
					0x31, 0x30, 0xc3, 0xd5, 0xff, 0xbc, 0x56, 0xe6,
					0xba, 0x18, 0xfa, 0xd8, 0x0e, 0x52, 0xb7, 0xfa,
					0x71, 0x54, 0xc1, 0x45, 0xf8, 0xdb, 0x95, 0xdc,
					0x67, 0x6f, 0x57, 0x46, 0xc8, 0xdc, 0x99, 0x91,
				},
				WarnOnly: false,
			},
			5: {
				Expected: [32]byte{
					0x7c, 0x10, 0xc9, 0x69, 0x4c, 0x5a, 0xe8, 0x80,
					0x61, 0x4d, 0x83, 0x54, 0x89, 0x93, 0x5c, 0xd9,
					0x6f, 0x76, 0x72, 0x3e, 0xe5, 0xa7, 0xec, 0x04,
					0xed, 0x76, 0xba, 0x48, 0xea, 0x20, 0x47, 0x37,
				},
				WarnOnly: true,
			},
			7: {
				Expected: [32]byte{
					0x34, 0x65, 0x47, 0xa8, 0xce, 0x59, 0x57, 0xaf,
					0x27, 0xe5, 0x52, 0x42, 0x7d, 0x6b, 0x9e, 0x6d,
					0x9c, 0xb5, 0x02, 0xf0, 0x15, 0x6e, 0x91, 0x55,
					0x38, 0x04, 0x51, 0xee, 0xa1, 0xb3, 0xf0, 0xed,
				},
				WarnOnly: true,
			},
			8: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			9: {
				Expected: [32]byte{
					0x41, 0xfd, 0xdf, 0xec, 0x81, 0x33, 0xd6, 0xd6,
					0xe8, 0x48, 0x35, 0x97, 0xf1, 0x09, 0xca, 0x5d,
					0xcc, 0xc8, 0x8e, 0x3e, 0xb3, 0x23, 0x83, 0xe7,
					0x60, 0x77, 0x61, 0x4a, 0xd4, 0x70, 0xb5, 0x7b,
				},
				WarnOnly: false,
			},
			11: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			12: {
				Expected: [32]byte{
					0xbb, 0x4c, 0xaa, 0xeb, 0x51, 0x07, 0x28, 0x44,
					0x7c, 0x98, 0xc2, 0x56, 0xa8, 0x43, 0xc2, 0x0c,
					0x6e, 0x3a, 0x91, 0x79, 0xd0, 0x1e, 0x0c, 0x93,
					0x9f, 0xa0, 0x00, 0x3b, 0x3d, 0xd1, 0x7e, 0xe8,
				},
				WarnOnly: false,
			},
			13: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			14: {
				Expected: [32]byte{
					0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22,
					0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9,
					0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c,
					0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f,
				},
				WarnOnly: true,
			},
			15: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
		}
	case cloudprovider.GCP:
		return M{
			0: {
				Expected: [32]byte{
					0x0f, 0x35, 0xc2, 0x14, 0x60, 0x8d, 0x93, 0xc7,
					0xa6, 0xe6, 0x8a, 0xe7, 0x35, 0x9b, 0x4a, 0x8b,
					0xe5, 0xa0, 0xe9, 0x9e, 0xea, 0x91, 0x07, 0xec,
					0xe4, 0x27, 0xc4, 0xde, 0xa4, 0xe4, 0x39, 0xcf,
				},
				WarnOnly: false,
			},
			1: {
				Expected: [32]byte{
					0x74, 0x5f, 0x2f, 0xb4, 0x23, 0x5e, 0x46, 0x47,
					0xaa, 0x0a, 0xd5, 0xac, 0xe7, 0x81, 0xcd, 0x92,
					0x9e, 0xb6, 0x8c, 0x28, 0x87, 0x0e, 0x7d, 0xd5,
					0xd1, 0xa1, 0x53, 0x58, 0x54, 0x32, 0x5e, 0x56,
				},
				WarnOnly: true,
			},
			2: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			3: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			4: {
				Expected: [32]byte{
					0x72, 0x16, 0x43, 0xc0, 0x2a, 0xa1, 0x6a, 0xc1,
					0x90, 0x7b, 0x69, 0x02, 0x27, 0xb0, 0xe6, 0x4d,
					0xb1, 0xae, 0x7a, 0x0c, 0xdb, 0x64, 0x59, 0xed,
					0x2d, 0x8f, 0xb6, 0x64, 0xdb, 0x9f, 0xa3, 0xca,
				},
				WarnOnly: false,
			},
			5: {
				Expected: [32]byte{
					0x86, 0xa2, 0x81, 0x2c, 0x36, 0xc4, 0xe2, 0x5d,
					0x15, 0xc2, 0xe3, 0x92, 0x43, 0x00, 0xb1, 0xf8,
					0xf9, 0x03, 0x57, 0x02, 0xf9, 0xbd, 0xe4, 0xe2,
					0x3d, 0xce, 0x80, 0xb5, 0x24, 0x9e, 0x42, 0x0d,
				},
				WarnOnly: true,
			},
			6: {
				Expected: [32]byte{
					0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
					0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
					0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
					0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69,
				},
				WarnOnly: true,
			},
			7: {
				Expected: [32]byte{
					0xb1, 0xe9, 0xb3, 0x05, 0x32, 0x5c, 0x51, 0xb9,
					0x3d, 0xa5, 0x8c, 0xbf, 0x7f, 0x92, 0x51, 0x2d,
					0x8e, 0xeb, 0xfa, 0x01, 0x14, 0x3e, 0x4d, 0x88,
					0x44, 0xe4, 0x0e, 0x06, 0x2e, 0x9b, 0x6c, 0xd5,
				},
				WarnOnly: true,
			},
			8: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			9: {
				Expected: [32]byte{
					0x1a, 0x57, 0xbd, 0xe3, 0x9e, 0xe9, 0x07, 0x00,
					0x6b, 0xe4, 0xed, 0xda, 0x1a, 0x12, 0xce, 0x05,
					0xf3, 0x21, 0x78, 0xe2, 0xa4, 0x01, 0x25, 0x50,
					0x63, 0xf5, 0x27, 0xfc, 0xe3, 0x64, 0x36, 0xc4,
				},
				WarnOnly: false,
			},
			10: {
				Expected: [32]byte{
					0x43, 0x76, 0x93, 0xf6, 0xb3, 0xad, 0xa9, 0x84,
					0xa7, 0xdf, 0x76, 0xd6, 0x1a, 0x74, 0xe6, 0xf6,
					0xe6, 0x06, 0xaa, 0xdf, 0x92, 0xdc, 0xcc, 0x2a,
					0x43, 0x60, 0x36, 0x5c, 0xe3, 0x77, 0x37, 0xd8,
				},
				WarnOnly: true,
			},
			11: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			12: {
				Expected: [32]byte{
					0x24, 0x0b, 0xbb, 0x2d, 0xe8, 0x14, 0x55, 0x2e,
					0x52, 0x15, 0x26, 0x62, 0x74, 0x66, 0x22, 0x74,
					0x11, 0xd4, 0x42, 0x62, 0x0c, 0x58, 0x99, 0x45,
					0x78, 0x90, 0xc6, 0xaf, 0x79, 0x68, 0xd8, 0x67,
				},
				WarnOnly: false,
			},
			13: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			14: {
				Expected: [32]byte{
					0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22,
					0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9,
					0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c,
					0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f,
				},
				WarnOnly: true,
			},
			15: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
		}
	case cloudprovider.QEMU:
		return M{
			4: {
				Expected: [32]byte{
					0xb4, 0x75, 0x9b, 0xb3, 0x42, 0x51, 0xa2, 0xd3,
					0x8b, 0x3f, 0x60, 0x11, 0x96, 0xa6, 0x8e, 0xa7,
					0x6d, 0xf7, 0xd3, 0x63, 0xb3, 0x12, 0xfc, 0xe9,
					0x5c, 0xb9, 0xbd, 0x68, 0x45, 0xe5, 0xe2, 0xae,
				},
				WarnOnly: false,
			},
			8: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			9: {
				Expected: [32]byte{
					0x33, 0xe4, 0x34, 0x57, 0x99, 0x6f, 0x8c, 0x01,
					0xdc, 0xe5, 0x28, 0x33, 0x89, 0xb9, 0x1e, 0xda,
					0x45, 0xd7, 0x5d, 0xdd, 0x1f, 0x42, 0x41, 0x46,
					0xa4, 0x57, 0x7b, 0x44, 0x61, 0xd4, 0xf3, 0xc5,
				},
				WarnOnly: false,
			},
			11: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			12: {
				Expected: [32]byte{
					0xb8, 0xdf, 0xc0, 0x57, 0x6c, 0xcc, 0xc7, 0x3e,
					0xa9, 0xe8, 0xad, 0x6a, 0x38, 0x4f, 0x6a, 0x69,
					0x99, 0xf8, 0x37, 0xb6, 0x53, 0x12, 0x35, 0x60,
					0xa7, 0x02, 0x3a, 0xfb, 0x90, 0x9d, 0x05, 0x3e,
				},
				WarnOnly: false,
			},
			13: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
			15: {
				Expected: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				WarnOnly: false,
			},
		}
	default:
		return nil
	}
}
