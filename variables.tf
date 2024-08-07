################################################################
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Licensed Materials - Property of IBM
#
# ©Copyright IBM Corp. 2020
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

################################################################
# Configure the IBM Cloud provider
################################################################
variable "ibmcloud_api_key" {
  type        = string
  description = "IBM Cloud API key associated with user's identity"
  default     = "<key>"

  validation {
    condition     = var.ibmcloud_api_key != "" && lower(var.ibmcloud_api_key) != "<key>"
    error_message = "The ibmcloud_api_key is required and cannot be empty."
  }
}

variable "service_instance_id" {
  type        = string
  description = "The cloud instance ID of your account"
  default     = ""

  validation {
    condition     = var.service_instance_id != "" && lower(var.service_instance_id) != "<cloud_instance_id>"
    error_message = "The service_instance_id is required and cannot be empty."
  }
}

variable "ibmcloud_region" {
  type        = string
  description = "The IBM Cloud region where you want to create the resources"
  default     = ""

  validation {
    condition     = var.ibmcloud_region != "" && lower(var.ibmcloud_region) != "<region>"
    error_message = "The ibmcloud_region is required and cannot be empty."
  }
}

variable "ibmcloud_zone" {
  type        = string
  description = "The zone of an IBM Cloud region where you want to create Power System resources"
  default     = ""

  validation {
    condition     = var.ibmcloud_zone != "" && lower(var.ibmcloud_zone) != "<zone>"
    error_message = "The ibmcloud_zone is required and cannot be empty."
  }
}

################################################################
# Configure the Instance details
################################################################

variable "bastion" {
  type = object({ count = number, memory = string, processors = string })
  default = {
    count      = 1
    memory     = "16"
    processors = "1"
  }
  validation {
    condition     = lookup(var.bastion, "count", 1) >= 1 && lookup(var.bastion, "count", 1) <= 2
    error_message = "The bastion.count value must be either 1 or 2."
  }
}

variable "bootstrap" {
  type = object({ count = number, memory = string, processors = string })
  default = {
    count      = 1
    memory     = "32"
    processors = "0.5"
  }
  validation {
    condition     = var.bootstrap["count"] == 0 || var.bootstrap["count"] == 1
    error_message = "The bootstrap.count value must be either 0 or 1."
  }
}

variable "master" {
  default = {
    count      = 3
    memory     = "32"
    processors = "0.5"
    #optional data volumes to master nodes
    #data_volume_size  = 100 #Default volume size (in GB) to be attached to the master nodes.
    #data_volume_count = 0 #Number of volumes to be attached to each master node.
  }
  validation {
    condition     = var.master["count"] == 3
    error_message = "The master.count value should be 3."
  }
}

variable "worker" {
  default = {
    count      = 2
    memory     = "32"
    processors = "0.5"
    #optional data volumes to worker nodes
    #data_volume_size  = 100 #Default volume size (in GB) to be attached to the worker nodes.
    #data_volume_count = 0 #Number of volumes to be attached to each worker node.
  }
}

variable "rhel_image_name" {
  type        = string
  description = "Name of the RHEL image that you want to use for the bastion node"
  default     = "rhel-8.3"
}

variable "rhcos_image_name" {
  type        = string
  description = "Name of the RHCOS image that you want to use for OCP nodes"
  default     = "rhcos-4.12"
}

variable "processor_type" {
  type        = string
  description = "The type of processor mode (shared/dedicated)"
  default     = "shared"
}

variable "system_type" {
  type        = string
  description = "The type of system (s922/e980)"
  default     = "s922"
}

variable "network_name" {
  type        = string
  description = "The name of the network to be used for deploy operations"
  default     = "ocp-net"

  validation {
    condition     = var.network_name != ""
    error_message = "The network_name is required and cannot be empty."
  }
}

variable "rhel_username" {
  type    = string
  default = "root"
}

variable "public_key_file" {
  type        = string
  description = "Path to public key file"
  default     = "data/id_rsa.pub"
  # if empty, will default to ${path.cwd}/data/id_rsa.pub
}

variable "private_key_file" {
  type        = string
  description = "Path to private key file"
  default     = "data/id_rsa"
  # if empty, will default to ${path.cwd}/data/id_rsa
}

variable "private_key" {
  type        = string
  description = "content of private ssh key"
  default     = ""
  # if empty, will read contents of file at var.private_key_file
}

variable "public_key" {
  type        = string
  description = "Public key"
  default     = ""
  # if empty, will read contents of file at var.public_key_file
}

variable "rhel_subscription_username" {
  type    = string
  default = ""
}

variable "rhel_subscription_password" {
  type    = string
  default = ""
}

variable "rhel_subscription_org" {
  type    = string
  default = ""
}

variable "rhel_subscription_activationkey" {
  type    = string
  default = ""
}
variable "rhel_smt" {
  type        = number
  description = "SMT value to set on the bastion node. Eg: on,off,2,4,8"
  default     = 4
}

################################################################
### IBM Cloud details
################################################################
variable "use_ibm_cloud_services" {
  type        = bool
  description = "Flag to use Internet Services (CIS) and Loadbalancer services on VPC instead of bastion services."
  default     = false
}
variable "ibm_cloud_vpc_name" {
  type        = string
  description = "Name of the IBM Cloud Virtual Private Clouds (VPC) to setup the load balancer. By default will create a new VPC when use_ibm_cloud_services=true."
  default     = ""
}
variable "ibm_cloud_vpc_subnet_name" {
  type        = string
  description = "Name of the VPC subnet having DirectLink access to the private network. By default will create a new VPC Subnet when use_ibm_cloud_services=true."
  default     = ""
}
variable "ibm_cloud_resource_group" {
  type        = string
  description = "Name of the IBM Cloud Resource Group where you want to create the VPC. Ignore if VPC and Subnet names are provided."
  default     = "Default"
}
variable "iaas_vpc_region" {
  type        = string
  description = "IBM Cloud VPC Infrastructure region."
  default     = ""
  # if empty, will default to ibmcloud_region
}
variable "ibm_cloud_cis_crn" {
  # cli: `ibmcloud resource service-instance <cis name>`
  type        = string
  description = "IBM Cloud Intenet Service instance CRN. Required if use_ibm_cloud_services = true."
  default     = ""
}
variable "ibm_cloud_tgw" {
  type        = string
  description = "Name of the existing transit gateway. If empty a new transit gateway will be created and connect VPC & PowerVS to it."
  default     = ""
}
variable "ibm_cloud_connection_name" {
  type        = string
  description = "Name of the existing cloud connection. If empty a new cloud connection will be created. Not applicable for PER."
  default     = ""
}

################################################################
### Instrumentation
################################################################
variable "ssh_agent" {
  type        = bool
  description = "Enable or disable SSH Agent. Can correct some connectivity issues. Default: false"
  default     = false
}

variable "connection_timeout" {
  description = "Timeout in minutes for SSH connections"
  default     = 30
}

variable "bastion_health_status" {
  type        = string
  description = "Specify if bastion should poll for the Health Status to be OK or WARNING. Default is OK."
  default     = "OK"
  validation {
    condition     = contains(["OK", "WARNING"], var.bastion_health_status)
    error_message = "The bastion_health_status value must be either OK or WARNING."
  }
}

variable "private_network_mtu" {
  type        = number
  description = "MTU value for the private network interface on RHEL and RHCOS nodes"
  default     = 1450
}

variable "installer_log_level" {
  type        = string
  description = "Set the log level required for openshift-install commands"
  default     = "info"
}

variable "helpernode_repo" {
  type        = string
  description = "Set the repo URL for using ocp4-helpernode"
  default     = "https://github.com/redhat-cop/ocp4-helpernode"
  # Repo for running ocp4 installations steps.
}

variable "helpernode_tag" {
  type        = string
  description = "Set the branch/tag name or commit# for using ocp4-helpernode repo"
  default     = "d1ab538df6aeba915bf056f7983a60a68717d4d9"
  # Checkout level for var.helpernode_repo which is used for setting up services required on bastion node
}

variable "install_playbook_repo" {
  type        = string
  description = "Set the repo URL for using ocp4-playbooks"
  default     = "https://github.com/ocp-power-automation/ocp4-playbooks"
  # Repo for running ocp4 installations steps.
}

variable "install_playbook_tag" {
  type        = string
  description = "Set the branch/tag name or commit# for using ocp4-playbooks repo"
  default     = "main"
  # Checkout level for var.install_playbook_repo which is used for running ocp4 installations steps
}

variable "ansible_extra_options" {
  type        = string
  description = "Extra options string to append to ansible-playbook commands"
  default     = "-v"
}

variable "ansible_repo_name" {
  default = "ansible-2.9-for-rhel-8-ppc64le-rpms"
}

variable "pull_secret_file" {
  type    = string
  default = "data/pull-secret.txt"

  validation {
    condition     = var.pull_secret_file != ""
    error_message = "The pull_secret_file is required and cannot be empty."
  }

  validation {
    condition     = fileexists(var.pull_secret_file)
    error_message = "The pull secret file doesn't exist."
  }

  validation {
    condition     = file(var.pull_secret_file) != ""
    error_message = "The pull secret file shouldn't be empty."
  }
}

variable "dns_forwarders" {
  type    = string
  default = "8.8.8.8; 8.8.4.4"
}

variable "rhcos_pre_kernel_options" {
  type        = list(string)
  description = "List of kernel arguments for the cluster nodes that for pre-installation"
  default     = []
}

variable "rhcos_kernel_options" {
  type        = list(string)
  description = "List of kernel arguments for the cluster nodes"
  default     = []
}

variable "node_labels" {
  type        = map(string)
  description = "Map of node labels for the cluster nodes"
  default     = {}
}

variable "chrony_config" {
  type        = bool
  description = "Set to true to setup time synchronization and setup chrony. Default: true"
  default     = true
}

variable "chrony_config_servers" {
  type = list(object({
    server  = string,
    options = string
  }))
  description = "List of ntp servers and options to apply"
  default     = []
  # example: chrony_config_servers = [ {server = "10.3.21.254", options = "iburst"}, {server = "10.5.21.254", options = "iburst"} ]
}

variable "setup_snat" {
  type        = bool
  description = "Flag to configure bastion as SNAT and use the router on all cluster nodes"
  default     = true
}

variable "setup_squid_proxy" {
  type        = bool
  description = "Flag to install and configure squid proxy server on bastion node"
  default     = false
}

# Applicable only when `setup_squid_proxy = false`
variable "proxy" {
  type        = object({})
  description = "External Proxy server details in a map"
  default     = {}
  #    default = {
  #        server = "10.10.1.166",
  #        port = "3128"
  #        user = "pxuser",
  #        password = "pxpassword"
  #    }
}

locals {
  private_key_file = var.private_key_file == "" ? "${path.cwd}/data/id_rsa" : var.private_key_file
  public_key_file  = var.public_key_file == "" ? "${path.cwd}/data/id_rsa.pub" : var.public_key_file
  private_key      = var.private_key == "" ? file(coalesce(local.private_key_file, "/dev/null")) : var.private_key
  public_key       = var.public_key == "" ? file(coalesce(local.public_key_file, "/dev/null")) : var.public_key
  iaas_vpc_region  = var.iaas_vpc_region == "" ? var.ibmcloud_region : var.iaas_vpc_region
}

################################################################
### OpenShift variables
################################################################
variable "openshift_install_tarball" {
  type    = string
  default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-install-linux.tar.gz"
}

variable "openshift_client_tarball" {
  type    = string
  default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-client-linux.tar.gz"
}

variable "release_image_override" {
  type    = string
  default = ""
}

# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
variable "cluster_domain" {
  type        = string
  default     = "ibm.com"
  description = "Domain name to use to setup the cluster. A CIS Domain should be a registered in IBM Cloud if use_ibm_cloud_services = true"

  validation {
    condition     = can(regex("^[a-z0-9]+[a-zA-Z0-9_\\-.]*[a-z0-9]+$", var.cluster_domain))
    error_message = "The cluster_domain value must be a lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character."
  }
}
# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
# Should not be more than 14 characters
variable "cluster_id_prefix" {
  type    = string
  default = "test-ocp"

  validation {
    condition     = can(regex("^$|^[a-z0-9]+[a-zA-Z0-9_\\-.]*[a-z0-9]+$", var.cluster_id_prefix))
    error_message = "The cluster_id_prefix value must be a lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character."
  }

  validation {
    condition     = length(var.cluster_id_prefix) <= 14
    error_message = "The cluster_id_prefix value shouldn't be greater than 14 characters."
  }
}
# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
# Length cannot exceed 14 characters when combined with cluster_id_prefix
variable "cluster_id" {
  type    = string
  default = ""

  validation {
    condition     = can(regex("^$|^[a-z0-9]+[a-zA-Z0-9_\\-.]*[a-z0-9]+$", var.cluster_id))
    error_message = "The cluster_id value must be a lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character."
  }

  validation {
    condition     = length(var.cluster_id) <= 14
    error_message = "The cluster_id value shouldn't be greater than 14 characters."
  }
}

variable "use_zone_info_for_names" {
  type        = bool
  default     = true
  description = "Add zone info to instance name or not"
}

variable "storage_type" {
  #Supported values: nfs (other value won't setup a storageclass)
  type    = string
  default = "nfs"
}

variable "volume_size" {
  # If storage_type = nfs, a new volume of this size will be attached to the bastion node.
  # Value in GB
  type    = string
  default = "300"
}

variable "volume_shareable" {
  type        = bool
  description = "If the volumes can be shared or not (true/false)"
  default     = false
}

variable "upgrade_image" {
  type        = string
  description = "OCP upgrade image e.g. quay.io/openshift-release-dev/ocp-release-nightly@sha256:xxxxx"
  default     = ""
}

variable "upgrade_version" {
  type        = string
  description = "OCP upgrade version"
  default     = ""
}

variable "upgrade_pause_time" {
  type        = string
  description = "Number of minutes to pause the playbook execution before starting to check the upgrade status once the upgrade command is executed."
  default     = "70"
}

variable "upgrade_delay_time" {
  type        = string
  description = "Number of seconds to wait before re-checking the upgrade status once the playbook execution resumes."
  default     = "600"
}

variable "eus_upgrade_version" {
  description = "OCP eus upgrade version eg. 4.11.4"
  default     = ""
}

variable "eus_upgrade_channel" {
  description = "Upgrade channel having required version availble for cluster upgrade (stable-4.x, fast-4.x, candidate-4.x, eus-4.x) eg. stable-4.11"
  default     = ""
}

variable "eus_upgrade_image" {
  description = "OCP upgrade image e.g. quay.io/openshift-release-dev/ocp-release-nightly@sha256:xxxxx"
  default     = ""
}

variable "eus_upstream" {
  description = "URL for OCP update server eg. https://ppc64le.ocp.releases.ci.openshift.org/graph"
  default     = ""
}

variable "cni_network_provider" {
  description = "Set the default Container Network Interface (CNI) network provider"
  default     = "OVNKubernetes"
}

variable "fips_compliant" {
  type        = bool
  description = "Set to true to enable usage of FIPS for OCP deployment."
  default     = false
}

################################################################
# Local registry variables ( used only for restricted network install )
################################################################
variable "enable_local_registry" {
  type        = bool
  description = "Set to true to enable usage of local registry for restricted network install."
  default     = false
}

variable "local_registry_image" {
  type        = string
  description = "Name of the image used for creating local registry container."
  default     = "docker.io/library/registry:2"
}

variable "ocp_release_tag" {
  type        = string
  description = "The version of OpenShift you want to sync."
  default     = "4.4.9-ppc64le"
}

variable "ocp_release_name" {
  type        = string
  description = "The release name of OpenShift you want to sync."
  default     = "ocp-release"
}

################################################################
# IBM Cloud DirectLink configuration variables
################################################################
variable "ibm_cloud_dl_endpoint_net_cidr" {
  type        = string
  description = "IBM Cloud DirectLink endpoint network cidr eg. 10.0.0.0/8"
  default     = ""
}

variable "ibm_cloud_http_proxy" {
  type        = string
  description = "IBM Cloud http/squid proxy eg. http://10.166.13.64:3128"
  default     = ""
}

################################################################
# CSI Driver installation variables
################################################################

variable "csi_driver_install" {
  type        = bool
  description = "Enable csi-driver installation (true/false)"
  default     = false
}

variable "csi_driver_type" {
  type        = string
  description = "Set to csi-driver type."
  default     = "stable"
}

variable "csi_driver_version" {
  type        = string
  description = "Set to csi-driver version."
  default     = "v0.1.1"
}

################################################################
# Image upload variables (used only for uploading RHCOS image
# from cloud object storage to PowerVS catalog)
################################################################
variable "rhcos_import_image" {
  type        = bool
  description = "Set to true to upload RHCOS image to PowerVS from Cloud Object Storage."
  default     = false
}

variable "rhcos_import_image_filename" {
  type        = string
  description = "Name of the RHCOS image object file. This file is expected to be in .owa.gz format"
  default     = "rhcos-411-85-202203181612-0-ppc64le-powervs.ova.gz"
}

variable "rhcos_import_image_storage_type" {
  type        = string
  description = "Storage type in PowerVS where the RHCOS image needs to be uploaded"
  default     = "tier1"
}

################################################################
# LUKS configuration variables
################################################################
variable "luks_compliant" {
  type        = bool
  description = "Set to true to enable usage of LUKS for OCP deployment."
  default     = false
}

variable "luks_config" {
  type = list(object({
    thumbprint = string,
    url        = string
  }))
  description = "List of tang servers and thumbprint to apply"
  default     = []
}

variable "luks_filesystem_device" {
  type        = string
  description = "Path of device to be luks encrypted"
  default     = "/dev/mapper/root"
}

variable "luks_format" {
  type        = string
  description = "Format of the FileSystem to be luks encrypted"
  default     = "xfs"
}

variable "luks_wipe_filesystem" {
  type        = bool
  description = "Configures the FileSystem to be wiped"
  default     = true
}

variable "luks_device" {
  type        = string
  description = "Path of luks encrypted partition"
  default     = "/dev/disk/by-partlabel/root"
}

variable "luks_label" {
  type        = string
  description = "Variable for the user label of luks encrpted partition"
  default     = "luks-root"
}

variable "luks_options" {
  type        = list(string)
  description = "List of luks options for the luks encryption"
  default     = ["--cipher", "aes-cbc-essiv:sha256"]
}

variable "luks_wipe_volume" {
  type        = bool
  description = "Configures the luks encrypted partition to be wiped"
  default     = true
}

variable "luks_name" {
  type        = string
  description = "Variable for the user label of Filesystem to be luks encrypted"
  default     = "root"
}


################################################################
# KDUMP variables
################################################################


variable "kdump_enable" {
  type        = bool
  description = "Set to true to enable the kdump on Cluster Nodes"
  default     = false
}
variable "kdump_commandline_remove" {
  type        = string
  description = "This option removes arguments from the current kdump command line"
  default     = "hugepages hugepagesz slub_debug quiet log_buf_len swiotlb"
}
variable "kdump_commandline_append" {
  type        = string
  description = "This option appends arguments to the current kdump command line"
  default     = "irqpoll maxcpus=1 reset_devices cgroup_disable=memory mce=off numa=off udev.children-max=2 panic=10 rootflags=nofail acpi_no_memhotplug transparent_hugepage=never nokaslr novmcoredd hest_disable srcutree.big_cpu_lim=0"
}
variable "kdump_kexec_args" {
  type        = string
  description = "For adding any extra argument to pass to kexec command"
  default     = "-s"
}
variable "kdump_img" {
  type        = string
  description = "For specifying image other than default kernel image"
  default     = "vmlinuz"
}
variable "kdump_log_path" {
  type        = string
  description = "The file system path in which the kdump saves the vmcore file"
  default     = "/var/crash"
}
variable "kdump_crash_kernel_memory" {
  type        = string
  description = "The crashkernel memory reservation for kdump occurs during the system boot"
  default     = "2G-4G:384M,4G-16G:512M,16G-64G:1G,64G-128G:2G,128G-:4G"
}
