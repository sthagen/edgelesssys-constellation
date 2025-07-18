/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// The provider package implements the Constellation Terraform provider's
// "provider" resource, which is the main entrypoint for Terraform to
// interact with the provider.
package provider

import (
	"context"
	"fmt"

	"github.com/edgelesssys/constellation/v2/internal/semver"
	datastruct "github.com/edgelesssys/constellation/v2/terraform-provider-constellation/internal/data"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Perform interface cast to ensure ConstellationProvider satisfies various provider interfaces.
var _ provider.Provider = &ConstellationProvider{}

// ConstellationProviderModel is the provider data model.
type ConstellationProviderModel struct{}

// ConstellationProvider is the provider implementation.
type ConstellationProvider struct {
	// version is set to the provider version on release, and the pseudo version on local builds. The pseudo version is not a valid default for the image_version attribute.
	version string
}

// New creates a new provider, based on a version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ConstellationProvider{
			version: version,
		}
	}
}

// Metadata returns the Providers name and version upon request.
func (p *ConstellationProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "constellation"
	resp.Version = p.version
}

// Schema defines the HCL schema of the provider, i.e. what attributes it has and what they are used for.
func (p *ConstellationProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The Constellation provider manages Constellation clusters.",
		MarkdownDescription: `The Constellation provider manages Constellation clusters.

Given user-defined infrastructure in Terraform, the provider with its main 'constellation_cluster' resource manages the entire lifecycle of a cluster.
The provider allows easy usage of custom infrastructure setups and GitOps workflows.
It is released as part of Constellation releases, such that each provider version is compatible with the corresponding Constellation version.`,
	}
}

// Configure is called when the provider block is initialized, and conventionally
// used to setup any API clients or other resources required for the provider.
func (p *ConstellationProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// Populate the provider configuration model with what the user supplied when
	// declaring the provider block. No-op for now, as no attributes are defined.
	var data ConstellationProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ver, err := semver.New(p.version)
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider version",
			fmt.Sprintf("Expected a valid semantic version, got %s: %s", p.version, err),
		)
		return
	}

	config := datastruct.ProviderData{
		Version: ver,
	}

	// Make the clients available during data source and resource "Configure" methods.
	resp.DataSourceData = config
	resp.ResourceData = config
}

// Resources lists the resources implemented by the provider.
func (p *ConstellationProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewClusterResource,
	}
}

// DataSources lists the data sources implemented by the provider.
func (p *ConstellationProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewImageDataSource, NewAttestationDataSource,
	}
}
