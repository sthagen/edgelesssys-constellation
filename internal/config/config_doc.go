// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Code generated by hack/docgen tool. DO NOT EDIT.

package config

import (
	"github.com/siderolabs/talos/pkg/machinery/config/encoder"
)

var (
	ConfigDoc         encoder.Doc
	UpgradeConfigDoc  encoder.Doc
	ProviderConfigDoc encoder.Doc
	AWSConfigDoc      encoder.Doc
	AzureConfigDoc    encoder.Doc
	GCPConfigDoc      encoder.Doc
	QEMUConfigDoc     encoder.Doc
)

func init() {
	ConfigDoc.Type = "Config"
	ConfigDoc.Comments[encoder.LineComment] = "Config defines configuration used by CLI."
	ConfigDoc.Description = "Config defines configuration used by CLI."
	ConfigDoc.Fields = make([]encoder.Doc, 7)
	ConfigDoc.Fields[0].Name = "version"
	ConfigDoc.Fields[0].Type = "string"
	ConfigDoc.Fields[0].Note = ""
	ConfigDoc.Fields[0].Description = "Schema version of this configuration file."
	ConfigDoc.Fields[0].Comments[encoder.LineComment] = "Schema version of this configuration file."
	ConfigDoc.Fields[1].Name = "image"
	ConfigDoc.Fields[1].Type = "string"
	ConfigDoc.Fields[1].Note = ""
	ConfigDoc.Fields[1].Description = "Machine image used to create Constellation nodes."
	ConfigDoc.Fields[1].Comments[encoder.LineComment] = "Machine image used to create Constellation nodes."
	ConfigDoc.Fields[2].Name = "stateDiskSizeGB"
	ConfigDoc.Fields[2].Type = "int"
	ConfigDoc.Fields[2].Note = ""
	ConfigDoc.Fields[2].Description = "Size (in GB) of a node's disk to store the non-volatile state."
	ConfigDoc.Fields[2].Comments[encoder.LineComment] = "Size (in GB) of a node's disk to store the non-volatile state."
	ConfigDoc.Fields[3].Name = "kubernetesVersion"
	ConfigDoc.Fields[3].Type = "string"
	ConfigDoc.Fields[3].Note = ""
	ConfigDoc.Fields[3].Description = "Kubernetes version to be installed in the cluster."
	ConfigDoc.Fields[3].Comments[encoder.LineComment] = "Kubernetes version to be installed in the cluster."
	ConfigDoc.Fields[4].Name = "debugCluster"
	ConfigDoc.Fields[4].Type = "bool"
	ConfigDoc.Fields[4].Note = ""
	ConfigDoc.Fields[4].Description = "DON'T USE IN PRODUCTION: enable debug mode and use debug images. For usage, see: https://github.com/edgelesssys/constellation/blob/main/debugd/README.md"
	ConfigDoc.Fields[4].Comments[encoder.LineComment] = "DON'T USE IN PRODUCTION: enable debug mode and use debug images. For usage, see: https://github.com/edgelesssys/constellation/blob/main/debugd/README.md"
	ConfigDoc.Fields[5].Name = "provider"
	ConfigDoc.Fields[5].Type = "ProviderConfig"
	ConfigDoc.Fields[5].Note = ""
	ConfigDoc.Fields[5].Description = "Supported cloud providers and their specific configurations."
	ConfigDoc.Fields[5].Comments[encoder.LineComment] = "Supported cloud providers and their specific configurations."
	ConfigDoc.Fields[6].Name = "upgrade"
	ConfigDoc.Fields[6].Type = "UpgradeConfig"
	ConfigDoc.Fields[6].Note = ""
	ConfigDoc.Fields[6].Description = "Configuration to apply during constellation upgrade."
	ConfigDoc.Fields[6].Comments[encoder.LineComment] = "Configuration to apply during constellation upgrade."

	ConfigDoc.Fields[6].AddExample("", UpgradeConfig{Image: "", Measurements: Measurements{}})

	UpgradeConfigDoc.Type = "UpgradeConfig"
	UpgradeConfigDoc.Comments[encoder.LineComment] = "UpgradeConfig defines configuration used during constellation upgrade."
	UpgradeConfigDoc.Description = "UpgradeConfig defines configuration used during constellation upgrade."

	UpgradeConfigDoc.AddExample("", UpgradeConfig{Image: "", Measurements: Measurements{}})
	UpgradeConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "Config",
			FieldName: "upgrade",
		},
	}
	UpgradeConfigDoc.Fields = make([]encoder.Doc, 3)
	UpgradeConfigDoc.Fields[0].Name = "image"
	UpgradeConfigDoc.Fields[0].Type = "string"
	UpgradeConfigDoc.Fields[0].Note = ""
	UpgradeConfigDoc.Fields[0].Description = "Updated Constellation machine image to install on all nodes."
	UpgradeConfigDoc.Fields[0].Comments[encoder.LineComment] = "Updated Constellation machine image to install on all nodes."
	UpgradeConfigDoc.Fields[1].Name = "measurements"
	UpgradeConfigDoc.Fields[1].Type = "Measurements"
	UpgradeConfigDoc.Fields[1].Note = ""
	UpgradeConfigDoc.Fields[1].Description = "Measurements of the updated image."
	UpgradeConfigDoc.Fields[1].Comments[encoder.LineComment] = "Measurements of the updated image."
	UpgradeConfigDoc.Fields[2].Name = "csp"
	UpgradeConfigDoc.Fields[2].Type = "Provider"
	UpgradeConfigDoc.Fields[2].Note = ""
	UpgradeConfigDoc.Fields[2].Description = "temporary field for upgrade migration\nTODO(AB#2654): Remove with refactoring upgrade plan command"
	UpgradeConfigDoc.Fields[2].Comments[encoder.LineComment] = "temporary field for upgrade migration"

	ProviderConfigDoc.Type = "ProviderConfig"
	ProviderConfigDoc.Comments[encoder.LineComment] = "ProviderConfig are cloud-provider specific configuration values used by the CLI."
	ProviderConfigDoc.Description = "ProviderConfig are cloud-provider specific configuration values used by the CLI.\nFields should remain pointer-types so custom specific configs can nil them\nif not required.\n"
	ProviderConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "Config",
			FieldName: "provider",
		},
	}
	ProviderConfigDoc.Fields = make([]encoder.Doc, 4)
	ProviderConfigDoc.Fields[0].Name = "aws"
	ProviderConfigDoc.Fields[0].Type = "AWSConfig"
	ProviderConfigDoc.Fields[0].Note = ""
	ProviderConfigDoc.Fields[0].Description = "Configuration for AWS as provider."
	ProviderConfigDoc.Fields[0].Comments[encoder.LineComment] = "Configuration for AWS as provider."
	ProviderConfigDoc.Fields[1].Name = "azure"
	ProviderConfigDoc.Fields[1].Type = "AzureConfig"
	ProviderConfigDoc.Fields[1].Note = ""
	ProviderConfigDoc.Fields[1].Description = "Configuration for Azure as provider."
	ProviderConfigDoc.Fields[1].Comments[encoder.LineComment] = "Configuration for Azure as provider."
	ProviderConfigDoc.Fields[2].Name = "gcp"
	ProviderConfigDoc.Fields[2].Type = "GCPConfig"
	ProviderConfigDoc.Fields[2].Note = ""
	ProviderConfigDoc.Fields[2].Description = "Configuration for Google Cloud as provider."
	ProviderConfigDoc.Fields[2].Comments[encoder.LineComment] = "Configuration for Google Cloud as provider."
	ProviderConfigDoc.Fields[3].Name = "qemu"
	ProviderConfigDoc.Fields[3].Type = "QEMUConfig"
	ProviderConfigDoc.Fields[3].Note = ""
	ProviderConfigDoc.Fields[3].Description = "Configuration for QEMU as provider."
	ProviderConfigDoc.Fields[3].Comments[encoder.LineComment] = "Configuration for QEMU as provider."

	AWSConfigDoc.Type = "AWSConfig"
	AWSConfigDoc.Comments[encoder.LineComment] = "AWSConfig are AWS specific configuration values used by the CLI."
	AWSConfigDoc.Description = "AWSConfig are AWS specific configuration values used by the CLI."
	AWSConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "ProviderConfig",
			FieldName: "aws",
		},
	}
	AWSConfigDoc.Fields = make([]encoder.Doc, 7)
	AWSConfigDoc.Fields[0].Name = "region"
	AWSConfigDoc.Fields[0].Type = "string"
	AWSConfigDoc.Fields[0].Note = ""
	AWSConfigDoc.Fields[0].Description = "AWS data center region. See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions"
	AWSConfigDoc.Fields[0].Comments[encoder.LineComment] = "AWS data center region. See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions"
	AWSConfigDoc.Fields[1].Name = "zone"
	AWSConfigDoc.Fields[1].Type = "string"
	AWSConfigDoc.Fields[1].Note = ""
	AWSConfigDoc.Fields[1].Description = "AWS data center zone name in defined region. See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-availability-zones"
	AWSConfigDoc.Fields[1].Comments[encoder.LineComment] = "AWS data center zone name in defined region. See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-availability-zones"
	AWSConfigDoc.Fields[2].Name = "instanceType"
	AWSConfigDoc.Fields[2].Type = "string"
	AWSConfigDoc.Fields[2].Note = ""
	AWSConfigDoc.Fields[2].Description = "VM instance type to use for Constellation nodes. Needs to support NitroTPM. See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html"
	AWSConfigDoc.Fields[2].Comments[encoder.LineComment] = "VM instance type to use for Constellation nodes. Needs to support NitroTPM. See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html"
	AWSConfigDoc.Fields[3].Name = "stateDiskType"
	AWSConfigDoc.Fields[3].Type = "string"
	AWSConfigDoc.Fields[3].Note = ""
	AWSConfigDoc.Fields[3].Description = "Type of a node's state disk. The type influences boot time and I/O performance. See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html"
	AWSConfigDoc.Fields[3].Comments[encoder.LineComment] = "Type of a node's state disk. The type influences boot time and I/O performance. See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html"
	AWSConfigDoc.Fields[4].Name = "iamProfileControlPlane"
	AWSConfigDoc.Fields[4].Type = "string"
	AWSConfigDoc.Fields[4].Note = ""
	AWSConfigDoc.Fields[4].Description = "Name of the IAM profile to use for the control plane nodes."
	AWSConfigDoc.Fields[4].Comments[encoder.LineComment] = "Name of the IAM profile to use for the control plane nodes."
	AWSConfigDoc.Fields[5].Name = "iamProfileWorkerNodes"
	AWSConfigDoc.Fields[5].Type = "string"
	AWSConfigDoc.Fields[5].Note = ""
	AWSConfigDoc.Fields[5].Description = "Name of the IAM profile to use for the worker nodes."
	AWSConfigDoc.Fields[5].Comments[encoder.LineComment] = "Name of the IAM profile to use for the worker nodes."
	AWSConfigDoc.Fields[6].Name = "measurements"
	AWSConfigDoc.Fields[6].Type = "Measurements"
	AWSConfigDoc.Fields[6].Note = ""
	AWSConfigDoc.Fields[6].Description = "Expected VM measurements."
	AWSConfigDoc.Fields[6].Comments[encoder.LineComment] = "Expected VM measurements."

	AzureConfigDoc.Type = "AzureConfig"
	AzureConfigDoc.Comments[encoder.LineComment] = "AzureConfig are Azure specific configuration values used by the CLI."
	AzureConfigDoc.Description = "AzureConfig are Azure specific configuration values used by the CLI."
	AzureConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "ProviderConfig",
			FieldName: "azure",
		},
	}
	AzureConfigDoc.Fields = make([]encoder.Doc, 15)
	AzureConfigDoc.Fields[0].Name = "subscription"
	AzureConfigDoc.Fields[0].Type = "string"
	AzureConfigDoc.Fields[0].Note = ""
	AzureConfigDoc.Fields[0].Description = "Subscription ID of the used Azure account. See: https://docs.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id#find-your-azure-subscription"
	AzureConfigDoc.Fields[0].Comments[encoder.LineComment] = "Subscription ID of the used Azure account. See: https://docs.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id#find-your-azure-subscription"
	AzureConfigDoc.Fields[1].Name = "tenant"
	AzureConfigDoc.Fields[1].Type = "string"
	AzureConfigDoc.Fields[1].Note = ""
	AzureConfigDoc.Fields[1].Description = "Tenant ID of the used Azure account. See: https://docs.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id#find-your-azure-ad-tenant"
	AzureConfigDoc.Fields[1].Comments[encoder.LineComment] = "Tenant ID of the used Azure account. See: https://docs.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id#find-your-azure-ad-tenant"
	AzureConfigDoc.Fields[2].Name = "location"
	AzureConfigDoc.Fields[2].Type = "string"
	AzureConfigDoc.Fields[2].Note = ""
	AzureConfigDoc.Fields[2].Description = "Azure datacenter region to be used. See: https://docs.microsoft.com/en-us/azure/availability-zones/az-overview#azure-regions-with-availability-zones"
	AzureConfigDoc.Fields[2].Comments[encoder.LineComment] = "Azure datacenter region to be used. See: https://docs.microsoft.com/en-us/azure/availability-zones/az-overview#azure-regions-with-availability-zones"
	AzureConfigDoc.Fields[3].Name = "resourceGroup"
	AzureConfigDoc.Fields[3].Type = "string"
	AzureConfigDoc.Fields[3].Note = ""
	AzureConfigDoc.Fields[3].Description = "Resource group for the cluster's resources. Must already exist."
	AzureConfigDoc.Fields[3].Comments[encoder.LineComment] = "Resource group for the cluster's resources. Must already exist."
	AzureConfigDoc.Fields[4].Name = "userAssignedIdentity"
	AzureConfigDoc.Fields[4].Type = "string"
	AzureConfigDoc.Fields[4].Note = ""
	AzureConfigDoc.Fields[4].Description = "Authorize spawned VMs to access Azure API."
	AzureConfigDoc.Fields[4].Comments[encoder.LineComment] = "Authorize spawned VMs to access Azure API."
	AzureConfigDoc.Fields[5].Name = "appClientID"
	AzureConfigDoc.Fields[5].Type = "string"
	AzureConfigDoc.Fields[5].Note = ""
	AzureConfigDoc.Fields[5].Description = "Application client ID of the Active Directory app registration."
	AzureConfigDoc.Fields[5].Comments[encoder.LineComment] = "Application client ID of the Active Directory app registration."
	AzureConfigDoc.Fields[6].Name = "clientSecretValue"
	AzureConfigDoc.Fields[6].Type = "string"
	AzureConfigDoc.Fields[6].Note = ""
	AzureConfigDoc.Fields[6].Description = "Client secret value of the Active Directory app registration credentials. Alternatively leave empty and pass value via CONSTELL_AZURE_CLIENT_SECRET_VALUE environment variable."
	AzureConfigDoc.Fields[6].Comments[encoder.LineComment] = "Client secret value of the Active Directory app registration credentials. Alternatively leave empty and pass value via CONSTELL_AZURE_CLIENT_SECRET_VALUE environment variable."
	AzureConfigDoc.Fields[7].Name = "instanceType"
	AzureConfigDoc.Fields[7].Type = "string"
	AzureConfigDoc.Fields[7].Note = ""
	AzureConfigDoc.Fields[7].Description = "VM instance type to use for Constellation nodes."
	AzureConfigDoc.Fields[7].Comments[encoder.LineComment] = "VM instance type to use for Constellation nodes."
	AzureConfigDoc.Fields[8].Name = "stateDiskType"
	AzureConfigDoc.Fields[8].Type = "string"
	AzureConfigDoc.Fields[8].Note = ""
	AzureConfigDoc.Fields[8].Description = "Type of a node's state disk. The type influences boot time and I/O performance. See: https://docs.microsoft.com/en-us/azure/virtual-machines/disks-types#disk-type-comparison"
	AzureConfigDoc.Fields[8].Comments[encoder.LineComment] = "Type of a node's state disk. The type influences boot time and I/O performance. See: https://docs.microsoft.com/en-us/azure/virtual-machines/disks-types#disk-type-comparison"
	AzureConfigDoc.Fields[9].Name = "deployCSIDriver"
	AzureConfigDoc.Fields[9].Type = "bool"
	AzureConfigDoc.Fields[9].Note = ""
	AzureConfigDoc.Fields[9].Description = "Deploy Azure Disk CSI driver with on-node encryption. For details see: https://docs.edgeless.systems/constellation/architecture/encrypted-storage"
	AzureConfigDoc.Fields[9].Comments[encoder.LineComment] = "Deploy Azure Disk CSI driver with on-node encryption. For details see: https://docs.edgeless.systems/constellation/architecture/encrypted-storage"
	AzureConfigDoc.Fields[10].Name = "confidentialVM"
	AzureConfigDoc.Fields[10].Type = "bool"
	AzureConfigDoc.Fields[10].Note = ""
	AzureConfigDoc.Fields[10].Description = "Use Confidential VMs. Always needs to be true."
	AzureConfigDoc.Fields[10].Comments[encoder.LineComment] = "Use Confidential VMs. Always needs to be true."
	AzureConfigDoc.Fields[11].Name = "secureBoot"
	AzureConfigDoc.Fields[11].Type = "bool"
	AzureConfigDoc.Fields[11].Note = ""
	AzureConfigDoc.Fields[11].Description = "Enable secure boot for VMs. If enabled, the OS image has to include a virtual machine guest state (VMGS) blob."
	AzureConfigDoc.Fields[11].Comments[encoder.LineComment] = "Enable secure boot for VMs. If enabled, the OS image has to include a virtual machine guest state (VMGS) blob."
	AzureConfigDoc.Fields[12].Name = "idKeyDigests"
	AzureConfigDoc.Fields[12].Type = "Digests"
	AzureConfigDoc.Fields[12].Note = ""
	AzureConfigDoc.Fields[12].Description = "List of accepted values for the field 'idkeydigest' in the AMD SEV-SNP attestation report. Only usable with ConfidentialVMs. See 4.6 and 7.3 in: https://www.amd.com/system/files/TechDocs/56860.pdf"
	AzureConfigDoc.Fields[12].Comments[encoder.LineComment] = "List of accepted values for the field 'idkeydigest' in the AMD SEV-SNP attestation report. Only usable with ConfidentialVMs. See 4.6 and 7.3 in: https://www.amd.com/system/files/TechDocs/56860.pdf"
	AzureConfigDoc.Fields[13].Name = "enforceIdKeyDigest"
	AzureConfigDoc.Fields[13].Type = "bool"
	AzureConfigDoc.Fields[13].Note = ""
	AzureConfigDoc.Fields[13].Description = "Enforce the specified idKeyDigest value during remote attestation."
	AzureConfigDoc.Fields[13].Comments[encoder.LineComment] = "Enforce the specified idKeyDigest value during remote attestation."
	AzureConfigDoc.Fields[14].Name = "measurements"
	AzureConfigDoc.Fields[14].Type = "Measurements"
	AzureConfigDoc.Fields[14].Note = ""
	AzureConfigDoc.Fields[14].Description = "Expected confidential VM measurements."
	AzureConfigDoc.Fields[14].Comments[encoder.LineComment] = "Expected confidential VM measurements."

	GCPConfigDoc.Type = "GCPConfig"
	GCPConfigDoc.Comments[encoder.LineComment] = "GCPConfig are GCP specific configuration values used by the CLI."
	GCPConfigDoc.Description = "GCPConfig are GCP specific configuration values used by the CLI."
	GCPConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "ProviderConfig",
			FieldName: "gcp",
		},
	}
	GCPConfigDoc.Fields = make([]encoder.Doc, 8)
	GCPConfigDoc.Fields[0].Name = "project"
	GCPConfigDoc.Fields[0].Type = "string"
	GCPConfigDoc.Fields[0].Note = ""
	GCPConfigDoc.Fields[0].Description = "GCP project. See: https://support.google.com/googleapi/answer/7014113?hl=en"
	GCPConfigDoc.Fields[0].Comments[encoder.LineComment] = "GCP project. See: https://support.google.com/googleapi/answer/7014113?hl=en"
	GCPConfigDoc.Fields[1].Name = "region"
	GCPConfigDoc.Fields[1].Type = "string"
	GCPConfigDoc.Fields[1].Note = ""
	GCPConfigDoc.Fields[1].Description = "GCP datacenter region. See: https://cloud.google.com/compute/docs/regions-zones#available"
	GCPConfigDoc.Fields[1].Comments[encoder.LineComment] = "GCP datacenter region. See: https://cloud.google.com/compute/docs/regions-zones#available"
	GCPConfigDoc.Fields[2].Name = "zone"
	GCPConfigDoc.Fields[2].Type = "string"
	GCPConfigDoc.Fields[2].Note = ""
	GCPConfigDoc.Fields[2].Description = "GCP datacenter zone. See: https://cloud.google.com/compute/docs/regions-zones#available"
	GCPConfigDoc.Fields[2].Comments[encoder.LineComment] = "GCP datacenter zone. See: https://cloud.google.com/compute/docs/regions-zones#available"
	GCPConfigDoc.Fields[3].Name = "serviceAccountKeyPath"
	GCPConfigDoc.Fields[3].Type = "string"
	GCPConfigDoc.Fields[3].Note = ""
	GCPConfigDoc.Fields[3].Description = "Path of service account key file. For required service account roles, see https://docs.edgeless.systems/constellation/getting-started/install#authorization"
	GCPConfigDoc.Fields[3].Comments[encoder.LineComment] = "Path of service account key file. For required service account roles, see https://docs.edgeless.systems/constellation/getting-started/install#authorization"
	GCPConfigDoc.Fields[4].Name = "instanceType"
	GCPConfigDoc.Fields[4].Type = "string"
	GCPConfigDoc.Fields[4].Note = ""
	GCPConfigDoc.Fields[4].Description = "VM instance type to use for Constellation nodes."
	GCPConfigDoc.Fields[4].Comments[encoder.LineComment] = "VM instance type to use for Constellation nodes."
	GCPConfigDoc.Fields[5].Name = "stateDiskType"
	GCPConfigDoc.Fields[5].Type = "string"
	GCPConfigDoc.Fields[5].Note = ""
	GCPConfigDoc.Fields[5].Description = "Type of a node's state disk. The type influences boot time and I/O performance. See: https://cloud.google.com/compute/docs/disks#disk-types"
	GCPConfigDoc.Fields[5].Comments[encoder.LineComment] = "Type of a node's state disk. The type influences boot time and I/O performance. See: https://cloud.google.com/compute/docs/disks#disk-types"
	GCPConfigDoc.Fields[6].Name = "deployCSIDriver"
	GCPConfigDoc.Fields[6].Type = "bool"
	GCPConfigDoc.Fields[6].Note = ""
	GCPConfigDoc.Fields[6].Description = "Deploy Persistent Disk CSI driver with on-node encryption. For details see: https://docs.edgeless.systems/constellation/architecture/encrypted-storage"
	GCPConfigDoc.Fields[6].Comments[encoder.LineComment] = "Deploy Persistent Disk CSI driver with on-node encryption. For details see: https://docs.edgeless.systems/constellation/architecture/encrypted-storage"
	GCPConfigDoc.Fields[7].Name = "measurements"
	GCPConfigDoc.Fields[7].Type = "Measurements"
	GCPConfigDoc.Fields[7].Note = ""
	GCPConfigDoc.Fields[7].Description = "Expected confidential VM measurements."
	GCPConfigDoc.Fields[7].Comments[encoder.LineComment] = "Expected confidential VM measurements."

	QEMUConfigDoc.Type = "QEMUConfig"
	QEMUConfigDoc.Comments[encoder.LineComment] = "QEMUConfig holds config information for QEMU based Constellation deployments."
	QEMUConfigDoc.Description = "QEMUConfig holds config information for QEMU based Constellation deployments."
	QEMUConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "ProviderConfig",
			FieldName: "qemu",
		},
	}
	QEMUConfigDoc.Fields = make([]encoder.Doc, 9)
	QEMUConfigDoc.Fields[0].Name = "imageFormat"
	QEMUConfigDoc.Fields[0].Type = "string"
	QEMUConfigDoc.Fields[0].Note = ""
	QEMUConfigDoc.Fields[0].Description = "Format of the image to use for the VMs. Should be either qcow2 or raw."
	QEMUConfigDoc.Fields[0].Comments[encoder.LineComment] = "Format of the image to use for the VMs. Should be either qcow2 or raw."
	QEMUConfigDoc.Fields[1].Name = "vcpus"
	QEMUConfigDoc.Fields[1].Type = "int"
	QEMUConfigDoc.Fields[1].Note = ""
	QEMUConfigDoc.Fields[1].Description = "vCPU count for the VMs."
	QEMUConfigDoc.Fields[1].Comments[encoder.LineComment] = "vCPU count for the VMs."
	QEMUConfigDoc.Fields[2].Name = "memory"
	QEMUConfigDoc.Fields[2].Type = "int"
	QEMUConfigDoc.Fields[2].Note = ""
	QEMUConfigDoc.Fields[2].Description = "Amount of memory per instance (MiB)."
	QEMUConfigDoc.Fields[2].Comments[encoder.LineComment] = "Amount of memory per instance (MiB)."
	QEMUConfigDoc.Fields[3].Name = "metadataAPIServer"
	QEMUConfigDoc.Fields[3].Type = "string"
	QEMUConfigDoc.Fields[3].Note = ""
	QEMUConfigDoc.Fields[3].Description = "Container image to use for the QEMU metadata server."
	QEMUConfigDoc.Fields[3].Comments[encoder.LineComment] = "Container image to use for the QEMU metadata server."
	QEMUConfigDoc.Fields[4].Name = "libvirtSocket"
	QEMUConfigDoc.Fields[4].Type = "string"
	QEMUConfigDoc.Fields[4].Note = ""
	QEMUConfigDoc.Fields[4].Description = "Libvirt connection URI. Leave empty to start a libvirt instance in Docker."
	QEMUConfigDoc.Fields[4].Comments[encoder.LineComment] = "Libvirt connection URI. Leave empty to start a libvirt instance in Docker."
	QEMUConfigDoc.Fields[5].Name = "libvirtContainerImage"
	QEMUConfigDoc.Fields[5].Type = "string"
	QEMUConfigDoc.Fields[5].Note = ""
	QEMUConfigDoc.Fields[5].Description = "Container image to use for launching a containerized libvirt daemon. Only relevant if `libvirtSocket = \"\"`."
	QEMUConfigDoc.Fields[5].Comments[encoder.LineComment] = "Container image to use for launching a containerized libvirt daemon. Only relevant if `libvirtSocket = \"\"`."
	QEMUConfigDoc.Fields[6].Name = "nvram"
	QEMUConfigDoc.Fields[6].Type = "string"
	QEMUConfigDoc.Fields[6].Note = ""
	QEMUConfigDoc.Fields[6].Description = "NVRAM template to be used for secure boot. Can be sentinel value \"production\", \"testing\" or a path to a custom NVRAM template"
	QEMUConfigDoc.Fields[6].Comments[encoder.LineComment] = "NVRAM template to be used for secure boot. Can be sentinel value \"production\", \"testing\" or a path to a custom NVRAM template"
	QEMUConfigDoc.Fields[7].Name = "firmware"
	QEMUConfigDoc.Fields[7].Type = "string"
	QEMUConfigDoc.Fields[7].Note = ""
	QEMUConfigDoc.Fields[7].Description = "Path to the OVMF firmware. Leave empty for auto selection."
	QEMUConfigDoc.Fields[7].Comments[encoder.LineComment] = "Path to the OVMF firmware. Leave empty for auto selection."
	QEMUConfigDoc.Fields[8].Name = "measurements"
	QEMUConfigDoc.Fields[8].Type = "Measurements"
	QEMUConfigDoc.Fields[8].Note = ""
	QEMUConfigDoc.Fields[8].Description = "Measurement used to enable measured boot."
	QEMUConfigDoc.Fields[8].Comments[encoder.LineComment] = "Measurement used to enable measured boot."
}

func (_ Config) Doc() *encoder.Doc {
	return &ConfigDoc
}

func (_ UpgradeConfig) Doc() *encoder.Doc {
	return &UpgradeConfigDoc
}

func (_ ProviderConfig) Doc() *encoder.Doc {
	return &ProviderConfigDoc
}

func (_ AWSConfig) Doc() *encoder.Doc {
	return &AWSConfigDoc
}

func (_ AzureConfig) Doc() *encoder.Doc {
	return &AzureConfigDoc
}

func (_ GCPConfig) Doc() *encoder.Doc {
	return &GCPConfigDoc
}

func (_ QEMUConfig) Doc() *encoder.Doc {
	return &QEMUConfigDoc
}

// GetConfigurationDoc returns documentation for the file ./config_doc.go.
func GetConfigurationDoc() *encoder.FileDoc {
	return &encoder.FileDoc{
		Name:        "Configuration",
		Description: "Definitions for  Constellation's user config file.\n\nThe config file is used by the CLI to create and manage a Constellation cluster.\n\nAll config relevant definitions, parsing and validation functions should go here.\n",
		Structs: []*encoder.Doc{
			&ConfigDoc,
			&UpgradeConfigDoc,
			&ProviderConfigDoc,
			&AWSConfigDoc,
			&AzureConfigDoc,
			&GCPConfigDoc,
			&QEMUConfigDoc,
		},
	}
}
