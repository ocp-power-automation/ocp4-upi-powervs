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

    validation{
        condition       = var.ibmcloud_api_key != "" && lower(var.ibmcloud_api_key) != "<key>"
        error_message   = "The ibmcloud_api_key is required and cannot be empty."
    }
}

variable "service_instance_id" {
    type        = string
    description = "The cloud instance ID of your account"
    default     = ""

    validation{
        condition       = var.service_instance_id != "" && lower(var.service_instance_id) != "<cloud_instance_id>"
        error_message   = "The service_instance_id is required and cannot be empty."
    }
}

variable "ibmcloud_region" {
    type        = string
    description = "The IBM Cloud region where you want to create the resources"
    default     = ""

    validation{
        condition       = var.ibmcloud_region != "" && lower(var.ibmcloud_region) != "<region>"
        error_message   = "The ibmcloud_region is required and cannot be empty."
    }
}

variable "ibmcloud_zone" {
    type        = string
    description = "The zone of an IBM Cloud region where you want to create Power System resources"
    default     = ""

    validation{
        condition       = var.ibmcloud_zone != "" && lower(var.ibmcloud_zone) != "<zone>"
        error_message   = "The ibmcloud_zone is required and cannot be empty."
    }
}

################################################################
# Configure the Instance details
################################################################

variable "bastion" {
    type    = object({ count = number, memory = string, processors = string })
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
    type    = object({ count = number, memory = string, processors = string })
    default = {
        count       = 1
        memory      = "32"
        processors  = "0.5"
    }
    validation {
        condition       = var.bootstrap["count"] == 0 || var.bootstrap["count"] == 1
        error_message   = "The bootstrap.count value must be either 0 or 1."
    }
}

variable "master" {
    type    = object({ count = number, memory = string, processors = string })
    default = {
        count       = 3
        memory      = "32"
        processors  = "0.5"
    }
    validation {
        condition       = var.master["count"] == 3
        error_message   = "The master.count value should be 3."
    }
}

variable "worker" {
    type    = object({ count = number, memory = string, processors = string })
    default = {
        count       = 2
        memory      = "32"
        processors  = "0.5"
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
    default     = "rhcos-4.7"
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

    validation{
        condition       = var.network_name != ""
        error_message   = "The network_name is required and cannot be empty."
    }
}

variable "rhel_username" {
    type    = string
    default = "root"
}

variable "public_key_file" {
    type        = string
    description = "Path to public key file"
    # if empty, will default to ${path.cwd}/data/id_rsa.pub
    default     = "data/id_rsa.pub"
}

variable "private_key_file" {
    type        = string
    description = "Path to private key file"
    # if empty, will default to ${path.cwd}/data/id_rsa
    default     = "data/id_rsa"
}

variable "private_key" {
    type        = string
    description = "content of private ssh key"
    # if empty string will read contents of file at var.private_key_file
    default     = ""
}

variable "public_key" {
    type        = string
    description = "Public key"
    # if empty string will read contents of file at var.public_key_file
    default     = ""
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
### Instrumentation
################################################################
variable "ssh_agent" {
    type        = bool
    description = "Enable or disable SSH Agent. Can correct some connectivity issues. Default: false"
    default     = false
}

variable "installer_log_level" {
    type        = string
    description = "Set the log level required for openshift-install commands"
    default     = "info"
}

variable "helpernode_repo" {
    type        = string
    description = "Set the repo URL for using ocp4-helpernode"
    # Repo for running ocp4 installations steps.
    default     = "https://github.com/RedHatOfficial/ocp4-helpernode"
}

variable "helpernode_tag" {
    type        = string
    description = "Set the branch/tag name or commit# for using ocp4-helpernode repo"
    # Checkout level for https://github.com/RedHatOfficial/ocp4-helpernode which is used for setting up services required on bastion node
    default     = "1ac7f276b537cd734240eda9ed554a254ba80629"
}

variable "install_playbook_repo" {
    type        = string
    description = "Set the repo URL for using ocp4-playbooks"
    # Repo for running ocp4 installations steps.
    default     = "https://github.com/ocp-power-automation/ocp4-playbooks"
}

variable "install_playbook_tag" {
    type        = string
    description = "Set the branch/tag name or commit# for using ocp4-playbooks repo"
    # Checkout level for https://github.com/ocp-power-automation/ocp4-playbooks which is used for running ocp4 installations steps
    default     = "592e51671ff2762718955fb2a0541a5b19c862e9"
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
    type      = string
    default   = "data/pull-secret.txt"

    validation{
        condition       = var.pull_secret_file != ""
        error_message   = "The pull_secret_file is required and cannot be empty."
    }

    validation{
        condition       = fileexists(var.pull_secret_file)
        error_message   = "The pull secret file doesn't exist."
    }

    validation{
        condition       = file(var.pull_secret_file) != ""
        error_message   = "The pull secret file shouldn't be empty."
    }
}

variable "dns_forwarders" {
    type      = string
    default   = "8.8.8.8; 8.8.4.4"
}

variable "rhcos_kernel_options" {
    type        = list(string)
    description = "List of kernel arguments for the cluster nodes"
    default     = []
}

variable "chrony_config" {
    type        = bool
    description = "Set to true to setup time synchronization and setup chrony. Default: true"
    default     = true
}

variable "chrony_config_servers" {
    type    = list(object({
        server  = string,
        options = string
    }))
    description = "List of ntp servers and options to apply"
    default     = []
    # example: chrony_config_servers = [ {server = "10.3.21.254", options = "iburst"}, {server = "10.5.21.254", options = "iburst"} ]
}

variable "setup_squid_proxy" {
    type        = bool
    description = "Flag to install and configure squid proxy server on bastion node"
    default     = true
}

# Applicable only when `setup_squid_proxy = false`
variable proxy {
    type         = object({})
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
    private_key_file    = var.private_key_file == "" ? "${path.cwd}/data/id_rsa" : var.private_key_file
    public_key_file     = var.public_key_file == "" ? "${path.cwd}/data/id_rsa.pub" : var.public_key_file
    private_key         = var.private_key == "" ? file(coalesce(local.private_key_file, "/dev/null")) : var.private_key
    public_key          = var.public_key == "" ? file(coalesce(local.public_key_file, "/dev/null")) : var.public_key
}

################################################################
### OpenShift variables
################################################################
variable "openshift_install_tarball" {
    type    = string
    default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.7/openshift-install-linux.tar.gz"
}

variable "openshift_client_tarball" {
    type    = string
    default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.7/openshift-client-linux.tar.gz"
}

variable "release_image_override" {
    type    = string
    default = ""
}

# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
variable "cluster_domain" {
    type    = string
    default = "ibm.com"

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
        condition     = can(regex("^[a-z0-9]+[a-zA-Z0-9_\\-.]*[a-z0-9]+$", var.cluster_id_prefix))
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

variable "volume_type" {
    type        = string
    description = "The volume type (ssd, standard, tier1, tier3)"
    default     = "tier3"
}

variable "volume_shareable" {
    type        = bool
    description = "If the volumes can be shared or not (true/false)"
    default     = false
}

variable "master_volume_size" {
    type        = string
    description = "Volume size to attach to the master nodes. If you don't need extra volume to be attached then keep the value empty"
    # Value in GB
    default     = ""
}

variable "worker_volume_size" {
    type        = string
    description = "Volume size to attach to the worker nodes. If you don't need extra volume to be attached then keep the value empty"
    # Value in GB
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

variable "cni_network_provider" {
    description = "Set the default Container Network Interface (CNI) network provider"
    default     = "OpenshiftSDN"
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
    default     = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
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
    type = string
    description = "IBM Cloud DirectLink endpoint network cidr eg. 10.0.0.0/8"
    default = ""
}

variable "ibm_cloud_http_proxy" {
    type = string
    description = "IBM Cloud http/squid proxy eg. http://10.166.13.64:3128"
    default = ""
}
