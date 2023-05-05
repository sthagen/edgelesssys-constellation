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
//go:generate measurement-generator

// DefaultsFor provides the default measurements for given cloud provider.
func DefaultsFor(provider cloudprovider.Provider) M {
	switch provider {
	case cloudprovider.AWS:
		return M{0: {Expected: [32]byte{0x73, 0x7f, 0x76, 0x7a, 0x12, 0xf5, 0x4e, 0x70, 0xee, 0xcb, 0xc8, 0x68, 0x40, 0x11, 0x32, 0x3a, 0xe2, 0xfe, 0x2d, 0xd9, 0xf9, 0x07, 0x85, 0x57, 0x79, 0x69, 0xd7, 0xa2, 0x01, 0x3e, 0x8c, 0x12}, ValidationOpt: WarnOnly}, 2: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 3: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 4: {Expected: [32]byte{0x62, 0x63, 0x70, 0x0d, 0x7d, 0xf3, 0xac, 0x13, 0xcc, 0x16, 0x91, 0x84, 0x9a, 0x34, 0xdd, 0x31, 0xc6, 0x98, 0xb8, 0x63, 0x60, 0xa2, 0x0a, 0xa5, 0x6e, 0x14, 0xe5, 0xa5, 0x53, 0x8a, 0x1a, 0x67}, ValidationOpt: Enforce}, 6: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 7: {Expected: [32]byte{0x12, 0x0e, 0x49, 0x8d, 0xb2, 0xa2, 0x24, 0xbd, 0x51, 0x2b, 0x6e, 0xfc, 0x9b, 0x02, 0x34, 0xf8, 0x43, 0xe1, 0x0b, 0xf0, 0x61, 0xeb, 0x7a, 0x76, 0xec, 0xca, 0x55, 0x09, 0xa2, 0x23, 0x89, 0x01}, ValidationOpt: WarnOnly}, 8: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 9: {Expected: [32]byte{0x9a, 0xb7, 0x4c, 0x11, 0x25, 0x31, 0xfd, 0x1f, 0xfc, 0x2b, 0x68, 0x40, 0xb3, 0xb5, 0x47, 0xa7, 0xcd, 0xb8, 0xdb, 0x88, 0x06, 0x78, 0x64, 0xdc, 0xf0, 0x01, 0x2d, 0xcc, 0xf5, 0x88, 0x60, 0xb5}, ValidationOpt: Enforce}, 11: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 12: {Expected: [32]byte{0xd9, 0x82, 0x9b, 0xb1, 0x26, 0x13, 0x73, 0x0e, 0x00, 0x8d, 0x25, 0xe4, 0x46, 0x6d, 0xbd, 0x1c, 0xc6, 0xdd, 0xce, 0xa7, 0xa2, 0x07, 0x3f, 0x51, 0xad, 0x2f, 0xea, 0xc7, 0xa2, 0xdf, 0xf4, 0x9b}, ValidationOpt: Enforce}, 13: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 14: {Expected: [32]byte{0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22, 0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9, 0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c, 0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f}, ValidationOpt: WarnOnly}, 15: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}}

	case cloudprovider.Azure:
		return M{1: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 2: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 3: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 4: {Expected: [32]byte{0x44, 0xbf, 0xbb, 0xe2, 0xf2, 0x5b, 0x28, 0x34, 0x05, 0x3a, 0x2d, 0x6c, 0xd8, 0x6e, 0xd0, 0x9d, 0x5f, 0xb9, 0x0f, 0x2a, 0x68, 0x4a, 0x27, 0x8d, 0xd5, 0x33, 0x83, 0x44, 0x49, 0xe5, 0x01, 0x69}, ValidationOpt: Enforce}, 7: {Expected: [32]byte{0x34, 0x65, 0x47, 0xa8, 0xce, 0x59, 0x57, 0xaf, 0x27, 0xe5, 0x52, 0x42, 0x7d, 0x6b, 0x9e, 0x6d, 0x9c, 0xb5, 0x02, 0xf0, 0x15, 0x6e, 0x91, 0x55, 0x38, 0x04, 0x51, 0xee, 0xa1, 0xb3, 0xf0, 0xed}, ValidationOpt: WarnOnly}, 8: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 9: {Expected: [32]byte{0xfd, 0x58, 0x2a, 0xb5, 0xbd, 0x07, 0x79, 0x9a, 0xd1, 0xe0, 0x40, 0x5a, 0xf9, 0x28, 0x0a, 0xf2, 0x85, 0x34, 0xb9, 0x8f, 0x50, 0x1d, 0xf1, 0x77, 0x75, 0x85, 0x86, 0x88, 0xbe, 0x3b, 0xc7, 0x68}, ValidationOpt: Enforce}, 11: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 12: {Expected: [32]byte{0xbc, 0x94, 0x4b, 0x15, 0xa9, 0xf9, 0xdc, 0x73, 0xef, 0xa0, 0x8b, 0xbb, 0x55, 0x78, 0x45, 0x06, 0x67, 0x1c, 0x50, 0xb2, 0xfd, 0xa7, 0x4e, 0x09, 0x49, 0x64, 0xd1, 0xc8, 0xf1, 0x1e, 0xb8, 0x5a}, ValidationOpt: Enforce}, 13: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 14: {Expected: [32]byte{0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22, 0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9, 0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c, 0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f}, ValidationOpt: WarnOnly}, 15: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}}

	case cloudprovider.GCP:
		return M{1: {Expected: [32]byte{0x74, 0x5f, 0x2f, 0xb4, 0x23, 0x5e, 0x46, 0x47, 0xaa, 0x0a, 0xd5, 0xac, 0xe7, 0x81, 0xcd, 0x92, 0x9e, 0xb6, 0x8c, 0x28, 0x87, 0x0e, 0x7d, 0xd5, 0xd1, 0xa1, 0x53, 0x58, 0x54, 0x32, 0x5e, 0x56}, ValidationOpt: WarnOnly}, 2: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 3: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 4: {Expected: [32]byte{0x9d, 0x98, 0xb7, 0xfb, 0x9c, 0x13, 0x62, 0xf4, 0xc0, 0x91, 0x92, 0x7a, 0x30, 0x25, 0x3b, 0x1e, 0x8b, 0x86, 0x97, 0x61, 0xba, 0x8e, 0x69, 0xb8, 0xec, 0xb8, 0xea, 0x93, 0x47, 0x5c, 0xf9, 0xfd}, ValidationOpt: Enforce}, 6: {Expected: [32]byte{0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69}, ValidationOpt: WarnOnly}, 7: {Expected: [32]byte{0xb1, 0xe9, 0xb3, 0x05, 0x32, 0x5c, 0x51, 0xb9, 0x3d, 0xa5, 0x8c, 0xbf, 0x7f, 0x92, 0x51, 0x2d, 0x8e, 0xeb, 0xfa, 0x01, 0x14, 0x3e, 0x4d, 0x88, 0x44, 0xe4, 0x0e, 0x06, 0x2e, 0x9b, 0x6c, 0xd5}, ValidationOpt: WarnOnly}, 8: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 9: {Expected: [32]byte{0xfd, 0x58, 0x2a, 0xb5, 0xbd, 0x07, 0x79, 0x9a, 0xd1, 0xe0, 0x40, 0x5a, 0xf9, 0x28, 0x0a, 0xf2, 0x85, 0x34, 0xb9, 0x8f, 0x50, 0x1d, 0xf1, 0x77, 0x75, 0x85, 0x86, 0x88, 0xbe, 0x3b, 0xc7, 0x68}, ValidationOpt: Enforce}, 11: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 12: {Expected: [32]byte{0x4a, 0x83, 0x0a, 0x52, 0xee, 0x6b, 0x09, 0x37, 0x17, 0x4a, 0x32, 0xef, 0xac, 0x28, 0x87, 0x59, 0x28, 0x58, 0xac, 0x53, 0x82, 0x88, 0x95, 0xce, 0xa8, 0x69, 0x2d, 0x5f, 0xf6, 0x34, 0xbe, 0x62}, ValidationOpt: Enforce}, 13: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 14: {Expected: [32]byte{0xd7, 0xc4, 0xcc, 0x7f, 0xf7, 0x93, 0x30, 0x22, 0xf0, 0x13, 0xe0, 0x3b, 0xde, 0xe8, 0x75, 0xb9, 0x17, 0x20, 0xb5, 0xb8, 0x6c, 0xf1, 0x75, 0x3c, 0xad, 0x83, 0x0f, 0x95, 0xe7, 0x91, 0x92, 0x6f}, ValidationOpt: WarnOnly}, 15: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}}

	case cloudprovider.QEMU:
		return M{4: {Expected: [32]byte{0xdd, 0xed, 0x12, 0x88, 0xeb, 0xbe, 0xb2, 0x1b, 0x61, 0xb7, 0x29, 0x5d, 0x41, 0x69, 0x5d, 0x6b, 0x59, 0xa8, 0x51, 0x08, 0xb4, 0x00, 0xe0, 0x20, 0xa8, 0x31, 0xaf, 0x5b, 0xcb, 0x2d, 0xae, 0xfb}, ValidationOpt: Enforce}, 8: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 9: {Expected: [32]byte{0x9a, 0xb7, 0x4c, 0x11, 0x25, 0x31, 0xfd, 0x1f, 0xfc, 0x2b, 0x68, 0x40, 0xb3, 0xb5, 0x47, 0xa7, 0xcd, 0xb8, 0xdb, 0x88, 0x06, 0x78, 0x64, 0xdc, 0xf0, 0x01, 0x2d, 0xcc, 0xf5, 0x88, 0x60, 0xb5}, ValidationOpt: Enforce}, 11: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 12: {Expected: [32]byte{0x9d, 0x44, 0x2d, 0x49, 0x7d, 0x8d, 0x3b, 0x12, 0x49, 0x01, 0xc8, 0x9b, 0xc6, 0x16, 0x8f, 0xb6, 0x21, 0xc1, 0x7c, 0x21, 0xbf, 0xb5, 0x01, 0xa0, 0xa1, 0xe5, 0x69, 0xc3, 0x7d, 0xe5, 0x9b, 0xdb}, ValidationOpt: Enforce}, 13: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}, 15: {Expected: [32]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ValidationOpt: Enforce}}

	default:
		return nil
	}
}
