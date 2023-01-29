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
# ©Copyright IBM Corp. 2023
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

variable "cluster_domain" {
  default = "example.com"
}
variable "cluster_id" {
  default = "test-ocp"
}

variable "dns_forwarders" {
  default = "8.8.8.8; 9.9.9.9"
}

variable "service_instance_id" {}
variable "region" {}
variable "zone" {}
variable "system_type" {}
variable "name_prefix" {}
variable "node_prefix" {}

variable "fips_compliant" {}
variable "gateway_ip" {}
variable "cidr" {}
variable "public_cidr" {}
variable "bastion_count" {}

variable "bastion_vip" {}
variable "bastion_ip" {}
variable "bastion_internal_vip" {}
variable "bastion_external_vip" {}
variable "bastion_public_ip" {}
variable "rhel_username" {}
variable "private_key" {}
variable "ssh_agent" {}
variable "connection_timeout" {}

variable "bootstrap_ip" {}
variable "master_ips" {}
variable "worker_ips" {}

variable "bootstrap_mac" {}
variable "master_macs" {}
variable "worker_macs" {}

variable "master_ids" {}
variable "worker_ids" {}

variable "openshift_client_tarball" {}
variable "openshift_install_tarball" {}

variable "public_key" {}
variable "pull_secret" {}
variable "release_image_override" {}

variable "private_network_mtu" {}

variable "enable_local_registry" {}
variable "local_registry_image" {}
variable "ocp_release_tag" {}
variable "ocp_release_name" {}

variable "helpernode_repo" { default = "https://github.com/redhat-cop/ocp4-helpernode" }
variable "helpernode_tag" { default = "main" }
variable "install_playbook_repo" { default = "https://github.com/ocp-power-automation/ocp4-playbooks" }
variable "install_playbook_tag" { default = "main" }

variable "storage_type" {}
variable "log_level" {}

variable "ansible_extra_options" {}
variable "rhcos_pre_kernel_options" {}
variable "rhcos_kernel_options" {}
variable "node_labels" {}
variable "chrony_config" { default = true }
variable "chrony_config_servers" {}

variable "upgrade_image" {}
variable "upgrade_version" {}
variable "upgrade_pause_time" {}
variable "upgrade_delay_time" {}

variable "eus_upgrade_version" {}
variable "eus_upgrade_channel" {}
variable "eus_upgrade_image" {}
variable "eus_upstream" {}

variable "setup_snat" {}

variable "setup_squid_proxy" {}
variable "proxy" {}

variable "ibm_cloud_dl_endpoint_net_cidr" {}
variable "ibm_cloud_http_proxy" {}

variable "cni_network_provider" {}

variable "use_ibm_cloud_services" {}
variable "vpc_cidr" {}

variable "ibmcloud_api_key" {}
variable "csi_driver_install" {}
variable "csi_driver_type" {}
variable "csi_driver_version" {}

variable "luks_compliant" { default = false }
variable "luks_config" {}
variable "luks_filesystem_device" {}
variable "luks_format" {}
variable "luks_wipe_filesystem" {}
variable "luks_device" {}
variable "luks_label" {}
variable "luks_options" {}
variable "luks_wipe_volume" {}
variable "luks_name" {}

variable "bootstrap_count" {}
variable "master_count" {}
variable "worker_count" {}
