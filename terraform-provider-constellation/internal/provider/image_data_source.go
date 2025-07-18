/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/edgelesssys/constellation/v2/internal/api/versionsapi"
	"github.com/edgelesssys/constellation/v2/internal/attestation/variant"
	"github.com/edgelesssys/constellation/v2/internal/cloud/cloudprovider"
	"github.com/edgelesssys/constellation/v2/internal/imagefetcher"
	"github.com/edgelesssys/constellation/v2/internal/semver"
	"github.com/edgelesssys/constellation/v2/terraform-provider-constellation/internal/data"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	// Ensure provider defined types fully satisfy framework interfaces.
	_                                       datasource.DataSource                   = &ImageDataSource{}
	_                                       datasource.DataSourceWithValidateConfig = &ImageDataSource{}
	_                                       datasource.DataSourceWithConfigure      = &ImageDataSource{}
	caseInsensitiveCommunityGalleriesRegexp                                         = regexp.MustCompile(`(?i)\/communitygalleries\/`)
	caseInsensitiveImagesRegExp                                                     = regexp.MustCompile(`(?i)\/images\/`)
	caseInsensitiveVersionsRegExp                                                   = regexp.MustCompile(`(?i)\/versions\/`)
)

// NewImageDataSource creates a new data source for fetching Constellation OS images
// from the Versions-API.
func NewImageDataSource() datasource.DataSource {
	return &ImageDataSource{}
}

// ImageDataSource defines the data source implementation for the image data source.
// It is used to retrieve the Constellation OS image reference for a given CSP and Attestation Variant.
type ImageDataSource struct {
	imageFetcher imageFetcher
	version      string
}

// imageFetcher gets an image reference from the versionsapi.
type imageFetcher interface {
	FetchReference(ctx context.Context,
		provider cloudprovider.Provider, attestationVariant variant.Variant,
		image, region string, useMarketplaceImage bool,
	) (string, error)
}

// ImageDataSourceModel defines the image data source's data model.
type ImageDataSourceModel struct {
	AttestationVariant types.String `tfsdk:"attestation_variant"`
	Version            types.String `tfsdk:"version"`
	CSP                types.String `tfsdk:"csp"`
	MarketplaceImage   types.Bool   `tfsdk:"marketplace_image"`
	Region             types.String `tfsdk:"region"`
	Image              types.Object `tfsdk:"image"`
}

// Metadata returns the metadata for the image data source.
func (d *ImageDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_image"
}

// Schema returns the schema for the image data source.
func (d *ImageDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The data source to resolve the CSP-specific OS image reference for a given version and attestation variant.",
		MarkdownDescription: "Data source to resolve the CSP-specific OS image reference for a given version and attestation variant.",
		Attributes: map[string]schema.Attribute{
			// Input Attributes
			"attestation_variant": newAttestationVariantAttributeSchema(attributeInput),
			"version": schema.StringAttribute{
				Description:         "Version of the Constellation OS image to use. (e.g. `v2.13.0`). If not set, the provider version is used.",
				MarkdownDescription: "Version of the Constellation OS image to use. (e.g. `v2.13.0`). If not set, the provider version value is used.",
				Optional:            true,
			},
			"csp": newCSPAttributeSchema(),
			"marketplace_image": schema.BoolAttribute{
				Description:         "Whether a marketplace image should be used.",
				MarkdownDescription: "Whether a marketplace image should be used.",
				Optional:            true,
			},
			"region": schema.StringAttribute{
				Description: "Region to retrieve the image for. Only required for AWS.",
				MarkdownDescription: "Region to retrieve the image for. Only required for AWS.\n" +
					"The Constellation OS image must be [replicated to the region](https://docs.edgeless.systems/constellation/workflows/config)," +
					"and the region must [support AMD SEV-SNP](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snp-requirements.html), if it is used for Attestation.",
				Optional: true,
			},
			// Output Attributes
			"image": newImageAttributeSchema(attributeOutput),
		},
	}
}

// ValidateConfig validates the configuration for the image data source.
func (d *ImageDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data ImageDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Region must be set for AWS
	if data.CSP.Equal(types.StringValue("aws")) && data.Region.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("region"),
			"Region must be set for AWS", "When csp is set to 'aws', 'region' must be specified.",
		)
	}

	// Setting Region for non-AWS CSPs has no effect
	if !data.CSP.Equal(types.StringValue("aws")) && !data.Region.IsNull() {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("region"),
			"Region should only be set for AWS", "When another CSP than AWS is used, setting 'region' has no effect.",
		)
	}

	// Version should be a valid semver or short path, if set
	if !data.Version.IsNull() {
		_, semverErr := semver.New(data.Version.ValueString())

		_, shortpathErr := versionsapi.NewVersionFromShortPath(data.Version.ValueString(), versionsapi.VersionKindImage)

		if semverErr != nil && shortpathErr != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("version"),
				"Invalid Version",
				fmt.Sprintf("When parsing the version (%s), an error occurred: %s", data.Version.ValueString(), errors.Join(semverErr, shortpathErr)),
			)
		}
	}
}

// Configure configures the data source.
func (d *ImageDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.imageFetcher = imagefetcher.New()

	// Prevent panic if the provider has not been configured. is necessary!
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(data.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected data.ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.version = providerData.Version.String()
}

// Read reads from the data source.
func (d *ImageDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	// Retrieve the configuration values for this data source instance.
	var data ImageDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	// Check configuration for errors.
	csp := cloudprovider.FromString(data.CSP.ValueString())
	if csp == cloudprovider.Unknown {
		resp.Diagnostics.AddAttributeError(
			path.Root("csp"),
			"Invalid CSP",
			fmt.Sprintf("Invalid CSP: %s", data.CSP.ValueString()),
		)
	}

	attestationVariant, err := variant.FromString(data.AttestationVariant.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("attestation_variant"),
			"Invalid Attestation Variant",
			fmt.Sprintf("When parsing the Attestation Variant (%s), an error occurred: %s", data.AttestationVariant.ValueString(), err),
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// lock-step with the provider
	imageVersion := data.Version.ValueString()
	if imageVersion == "" {
		tflog.Info(ctx, fmt.Sprintf("No image version specified, using provider version %s", d.version))
		imageVersion = d.version // Use provider version as default.
	}

	// determine semver from version string
	var imageSemver string
	var apiCompatibleVer versionsapi.Version
	if strings.HasPrefix(imageVersion, "v") {
		// If the version is a release version, it should look like vX.Y.Z
		imageSemver = imageVersion
		apiCompatibleVer, err = versionsapi.NewVersion(
			versionsapi.ReleaseRef,
			"stable",
			imageVersion,
			versionsapi.VersionKindImage,
		)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("version"),
				"Invalid Version",
				fmt.Sprintf("When parsing the version (%s), an error occurred: %s", imageVersion, err),
			)
			return
		}
	} else {
		// otherwise, it should be a versionsapi short path
		apiCompatibleVer, err = versionsapi.NewVersionFromShortPath(imageVersion, versionsapi.VersionKindImage)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("version"),
				"Invalid Version",
				fmt.Sprintf("When parsing the version (%s), an error occurred: %s", imageVersion, err),
			)
			return
		}
		imageSemver = apiCompatibleVer.Version()
	}

	// Retrieve Image Reference
	imageRef, err := d.imageFetcher.FetchReference(ctx, csp, attestationVariant,
		imageVersion, data.Region.ValueString(), data.MarketplaceImage.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error fetching Image Reference",
			fmt.Sprintf("When fetching the image reference, an error occurred: %s", err),
		)
		return
	}

	// Do adjustments for Azure casing
	if csp == cloudprovider.Azure {
		imageRef = caseInsensitiveCommunityGalleriesRegexp.ReplaceAllString(imageRef, "/communityGalleries/")
		imageRef = caseInsensitiveImagesRegExp.ReplaceAllString(imageRef, "/images/")
		imageRef = caseInsensitiveVersionsRegExp.ReplaceAllString(imageRef, "/versions/")
	}

	// Save data into Terraform state
	diags := resp.State.SetAttribute(ctx, path.Root("image"), imageAttribute{
		Reference:        imageRef,
		Version:          imageSemver,
		ShortPath:        apiCompatibleVer.ShortPath(),
		MarketplaceImage: data.MarketplaceImage.ValueBoolPointer(),
	})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
