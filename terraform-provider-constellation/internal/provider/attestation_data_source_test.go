/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package provider

import (
	"errors"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAttestationSource(t *testing.T) {
	// Set the path to the Terraform binary for acceptance testing when running under Bazel.
	bazelPreCheck := func() { bazelSetTerraformBinaryPath(t) }

	assertNonZeroValue := func(attr string) resource.TestCheckFunc {
		return resource.TestCheckResourceAttrWith(
			"data.constellation_attestation.test",
			attr,
			func(value string) error {
				parsedValue, err := strconv.ParseUint(value, 10, 8)
				if err == nil && parsedValue == 0 {
					return errors.New("expected non-zero value")
				}
				return err
			},
		)
	}
	assertUint8Value := func(attr string) resource.TestCheckFunc {
		return resource.TestCheckResourceAttrWith(
			"data.constellation_attestation.test",
			attr,
			func(value string) error {
				_, err := strconv.ParseUint(value, 10, 8)
				return err
			},
		)
	}

	testCases := map[string]resource.TestCase{
		"azure sev-snp success": {
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			PreCheck:                 bazelPreCheck,
			Steps: []resource.TestStep{
				{
					Config: testingConfig + `
					data "constellation_attestation" "test" {
						csp = "azure"
						attestation_variant = "azure-sev-snp"
						image = {
							version = "v2.13.0"
							reference = "v2.13.0"
							short_path = "v2.13.0"
						}
						maa_url = "https://www.example.com"
					}
					`,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.variant", "azure-sev-snp"),
						assertNonZeroValue("attestation.bootloader_version"),
						assertNonZeroValue("attestation.microcode_version"),
						assertNonZeroValue("attestation.snp_version"),
						assertUint8Value("attestation.tee_version"), // the valid value is 0 at the moment
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.azure_firmware_signer_config.accepted_key_digests.0", "0356215882a825279a85b300b0b742931d113bf7e32dde2e50ffde7ec743ca491ecdd7f336dc28a6e0b2bb57af7a44a3"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.azure_firmware_signer_config.enforcement_policy", "MAAFallback"),

						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.amd_root_key", "\"-----BEGIN CERTIFICATE-----\\nMIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC\\nBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS\\nBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg\\nQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp\\nY2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy\\nMTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS\\nBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j\\nZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG\\n9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg\\nW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta\\n1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2\\nSzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0\\n60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05\\ngmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg\\nbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs\\n+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi\\nQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ\\neTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18\\nfHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j\\nWhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI\\nrFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG\\nKWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG\\nSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI\\nAWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel\\nETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw\\nSTjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK\\ndHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq\\nzT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp\\nKGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e\\npmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq\\nHnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh\\n3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn\\nJZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH\\nCViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4\\nAFZEAwoKCQ==\\n-----END CERTIFICATE-----\\n\""),

						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.1.expected", "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.1.warn_only", "true"),
					),
				},
			},
		},
		"azure tdx success": {
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			PreCheck:                 bazelPreCheck,
			Steps: []resource.TestStep{
				{
					Config: testingConfig + `
					data "constellation_attestation" "test" {
						csp = "azure"
						attestation_variant = "azure-tdx"
						image = {
							version = "v2.15.0"
							reference = "v2.15.0"
							short_path = "v2.15.0"
						}
						insecure = true
					}
					`,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.variant", "azure-tdx"),

						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.bootloader_version", "0"), // not support for TDX
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.tdx.pce_svn", "0"),        // Current default value for TDX

						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.tdx.intel_root_key", `"-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n"`),

						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.15.expected", "0000000000000000000000000000000000000000000000000000000000000000"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.15.warn_only", "false"),
					),
				},
			},
		},
		"gcp sev-es succcess": {
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			PreCheck:                 bazelPreCheck,
			Steps: []resource.TestStep{
				{
					Config: testingConfig + `
					data "constellation_attestation" "test" {
						csp = "gcp"
						attestation_variant = "gcp-sev-es"
						image = {
							version = "v2.13.0"
							reference = "v2.13.0"
							short_path = "v2.13.0"
						}
					}
					`,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.variant", "gcp-sev-es"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.bootloader_version", "0"), // since this is not supported on GCP, we expect 0

						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.1.expected", "745f2fb4235e4647aa0ad5ace781cd929eb68c28870e7dd5d1a1535854325e56"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.1.warn_only", "true"),
					),
				},
			},
		},
		"gcp sev-snp succcess": {
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			PreCheck:                 bazelPreCheck,
			Steps: []resource.TestStep{
				{
					Config: testingConfig + `
					data "constellation_attestation" "test" {
						csp = "gcp"
						attestation_variant = "gcp-sev-snp"
						image = {
							version = "v2.17.0"
							reference = "v2.17.0"
							short_path = "v2.17.0"
						}
					}
					`,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.variant", "gcp-sev-snp"),
						assertNonZeroValue("attestation.bootloader_version"),
						assertNonZeroValue("attestation.microcode_version"),
						assertNonZeroValue("attestation.snp_version"),
						assertUint8Value("attestation.tee_version"), // the valid value is 0 at the moment
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.1.expected", "3695dcc55e3aa34027c27793c85c723c697d708c42d1f73bd6fa4f26608a5b24"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.1.warn_only", "true"),
					),
				},
			},
		},
		"STACKIT qemu-vtpm success": {
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			PreCheck:                 bazelPreCheck,
			Steps: []resource.TestStep{
				{
					Config: testingConfig + `
					data "constellation_attestation" "test" {
						csp = "stackit"
						attestation_variant = "qemu-vtpm"
						image = {
							version = "v2.13.0"
							reference = "v2.13.0"
							short_path = "v2.13.0"
						}
					}
					`,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.variant", "qemu-vtpm"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.bootloader_version", "0"), // since this is not supported on STACKIT, we expect 0

						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.15.expected", "0000000000000000000000000000000000000000000000000000000000000000"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.15.warn_only", "false"),
					),
				},
			},
		},
		"openstack qemu-vtpm success": {
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			PreCheck:                 bazelPreCheck,
			Steps: []resource.TestStep{
				{
					Config: testingConfig + `
					data "constellation_attestation" "test" {
						csp = "openstack"
						attestation_variant = "qemu-vtpm"
						image = {
							version = "v2.13.0"
							reference = "v2.13.0"
							short_path = "v2.13.0"
						}
					}
					`,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.variant", "qemu-vtpm"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.bootloader_version", "0"), // since this is not supported on OpenStack, we expect 0

						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.15.expected", "0000000000000000000000000000000000000000000000000000000000000000"),
						resource.TestCheckResourceAttr("data.constellation_attestation.test", "attestation.measurements.15.warn_only", "false"),
					),
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, tc)
		})
	}
}
