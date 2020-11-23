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
    description = "IBM Cloud API key associated with user's identity"
    default = "<key>"
}

variable "service_instance_id" {
    description = "The cloud instance ID of your account"
    default = ""
}

variable "ibmcloud_region" {
    description = "The IBM Cloud region where you want to create the resources"
    default = ""
}

variable "ibmcloud_zone" {
    description = "The zone of an IBM Cloud region where you want to create Power System resources"
    default = ""
}

################################################################
# Configure the Instance details
################################################################

variable "bastion" {
    # only one node is supported
    default = {
        count       = 1
        memory      = "16"
        processors  = "1"
    }
    validation {
        condition       = lookup(var.bastion, "count", 1) >= 1 && lookup(var.bastion, "count", 1) <= 2
        error_message   = "The bastion.count value must be either 1 or 2."
    }
}

variable "bootstrap" {
    default = {
        count       = 1
        memory      = "16"
        processors  = "0.5"
    }
    validation {
        condition       = var.bootstrap["count"] == 0 || var.bootstrap["count"] == 1
        error_message   = "The bootstrap.count value must be either 0 or 1."
    }
}

variable "master" {
    default = {
        count       = 3
        memory      = "16"
        processors  = "0.5"
    }
}

variable "worker" {
    default = {
        count       = 2
        memory      = "16"
        processors  = "0.5"
    }
}

variable "rhel_image_name" {
    description = "Name of the RHEL image that you want to use for the bastion node"
    default = "rhel-8.2"
}

variable "rhcos_image_name" {
    description = "Name of the RHCOS image that you want to use for OCP nodes"
    default = "rhcos-4.6"
}

variable "processor_type" {
    description = "The type of processor mode (shared/dedicated)"
    default = "shared"
}

variable "system_type" {
    description = "The type of system (s922/e980)"
    default = "s922"
}

variable "network_name" {
    description = "The name of the network to be used for deploy operations"
    default = "my_network_name"
}

variable "rhel_username" {
    default = "root"
}

variable "public_key_file" {
    description = "Path to public key file"
    # if empty, will default to ${path.cwd}/data/id_rsa.pub
    default     = "data/id_rsa.pub"
}

variable "private_key_file" {
    description = "Path to private key file"
    # if empty, will default to ${path.cwd}/data/id_rsa
    default     = "data/id_rsa"
}

variable "private_key" {
    description = "content of private ssh key"
    # if empty string will read contents of file at var.private_key_file
    default = ""
}

variable "public_key" {
    description = "Public key"
    # if empty string will read contents of file at var.public_key_file
    default     = ""
}

variable "rhel_subscription_username" {
    default = ""
}

variable "rhel_subscription_password" {
    default = ""
}

variable "rhel_smt" {
    description = "SMT value to set on the bastion node. Eg: on,off,2,4,8"
    default = 4
}

################################################################
### Instrumentation
################################################################
variable "ssh_agent" {
    description = "Enable or disable SSH Agent. Can correct some connectivity issues. Default: false"
    default     = false
}

variable "installer_log_level" {
    description = "Set the log level required for openshift-install commands"
    default = "info"
}

variable "helpernode_repo" {
    description = "Set the repo URL for using ocp4-helpernode"
    # Repo for running ocp4 installations steps.
    default = "https://github.com/RedHatOfficial/ocp4-helpernode"
}

variable "helpernode_tag" {
    description = "Set the branch/tag name or commit# for using ocp4-helpernode repo"
    # Checkout level for https://github.com/RedHatOfficial/ocp4-helpernode which is used for setting up services required on bastion node
    default = "dd8a0767c677fc862e45b6d70e5d04656ced5d28"
}

variable "install_playbook_repo" {
    description = "Set the repo URL for using ocp4-playbooks"
    # Repo for running ocp4 installations steps.
    default = "https://github.com/ocp-power-automation/ocp4-playbooks"
}

variable "install_playbook_tag" {
    description = "Set the branch/tag name or commit# for using ocp4-playbooks repo"
    # Checkout level for https://github.com/ocp-power-automation/ocp4-playbooks which is used for running ocp4 installations steps
    default = "6adcde2b1cab38d52441a6cd54023869f569884e"
}

variable "ansible_extra_options" {
    description = "Extra options string to append to ansible-playbook commands"
    default     = "-v"
}

variable "pull_secret_file" {
    default   = "data/pull-secret.txt"
}

variable "dns_forwarders" {
    default   = "8.8.8.8; 8.8.4.4"
}

variable "rhcos_kernel_options" {
    description = "List of kernel arguments for the cluster nodes"
    default     = []
}

variable "chrony_config" {
    description = "Set to true to setup time synchronization and setup chrony. Default: true"
    default     = true
}

variable "chrony_config_servers" {
    description = "List of ntp servers and options to apply"
    default     = []
    # example: chrony_config_servers = [ {server = "10.3.21.254", options = "iburst"}, {server = "10.5.21.254", options = "iburst"} ]
}

variable "setup_squid_proxy" {
    description = "Flag to install and configure squid proxy server on bastion node"
    default     = true
}

# Applicable only when `setup_squid_proxy = false`
variable proxy {
    description = "External Proxy server details in a map"
    default = {}
#    default = {
#        server = "10.10.1.166",
#        port = "3128"
#        user = "pxuser",
#        password = "pxpassword"
#    }
}

locals {
    private_key_file    = var.private_key_file == "" ? "${path.cwd}/data/id_rsa" : var.private_key_file
    public_key_file     = var.public_key_file == "" ? "${path.cwd}/data/id_rsa.pub" : var.public_key_file
    private_key         = var.private_key == "" ? file(coalesce(local.private_key_file, "/dev/null")) : var.private_key
    public_key          = var.public_key == "" ? file(coalesce(local.public_key_file, "/dev/null")) : var.public_key
}

################################################################
### OpenShift variables
################################################################
variable "openshift_install_tarball" {
    default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-install-linux.tar.gz"
}

variable "openshift_client_tarball" {
    default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-client-linux.tar.gz"
}

variable "release_image_override" {
    default = ""
}

# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
variable "cluster_domain" {
    default   = "ibm.com"
}
# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
# Should not be more than 14 characters
variable "cluster_id_prefix" {
    default   = "test-ocp"
}
# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
# Length cannot exceed 14 characters when combined with cluster_id_prefix
variable "cluster_id" {
    default   = ""
}

variable "storage_type" {
    #Supported values: nfs (other value won't setup a storageclass)
    default = "nfs"
}

variable "volume_size" {
    # If storage_type = nfs, a new volume of this size will be attached to the bastion node.
    # Value in GB
    default = "300"
}

variable "volume_type" {
    description = "The volume type (ssd, standard, tier1, tier3)"
    default = "tier3"
}

variable "volume_shareable" {
    description = "If the volumes can be shared or not (true/false)"
    default = false
}

variable "master_volume_size" {
    description = "Volume size to attach to the master nodes. If you don't need extra volume to be attached then keep the value empty"
    # Value in GB
    default = ""
}

variable "worker_volume_size" {
    description = "Volume size to attach to the worker nodes. If you don't need extra volume to be attached then keep the value empty"
    # Value in GB
    default = ""
}

variable "upgrade_image" {
    description = "OCP upgrade image"
    default = ""
}

variable "upgrade_pause_time" {
    description = "Number of minutes to pause the playbook execution before starting to check the upgrade status once the upgrade command is executed."
    default = "90"
}

variable "upgrade_delay_time" {
    description = "Number of seconds to wait before re-checking the upgrade status once the playbook execution resumes."
    default = "600"
}

################################################################
# Local registry variables ( used only for restricted network install )
################################################################
variable "enable_local_registry" {
  type = bool
  description = "Set to true to enable usage of local registry for restricted network install."
  default = false
}

variable "local_registry_image" {
    description = "Name of the image used for creating local registry container."
    default = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
}

variable "ocp_release_tag" {
    description = "The version of OpenShift you want to sync."
    default = "4.4.9-ppc64le"
}

variable "ocp_release_name" {
    description = "The release name of OpenShift you want to sync."
    default = "ocp-release"
}

################################################################
# IBM Cloud DirectLink configuration variables
################################################################
variable "ibm_cloud_dl_endpoint_net_cidr" {
    type = string
    description = "IBM Cloud DirectLink endpoint network cidr eg. 10.0.0.0/8"
    default = ""
}

variable "ibm_cloud_http_proxy" {
    type = string
    description = "IBM Cloud http/squid proxy eg. http://10.166.13.64:3128"
    default = ""
}
