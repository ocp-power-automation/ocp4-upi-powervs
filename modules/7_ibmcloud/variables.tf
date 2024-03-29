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
# ©Copyright IBM Corp. 2021
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
variable "name_prefix" {}
variable "node_prefix" {}

variable "vpc_name" {}
variable "vpc_subnet_name" {}
variable "vpc_region" {}
variable "ibm_cloud_resource_group" {}
variable "ibm_cloud_cis_crn" {}
variable "ibm_cloud_tgw" {}
variable "ibm_cloud_tgw_net" {}
variable "is_per" {}
variable "is_new_cloud_connection" {}

variable "bastion_count" {}
variable "bootstrap_count" {}
variable "master_count" {}
variable "worker_count" {}

variable "bastion_vip" {}
variable "bastion_ip" {}

variable "bootstrap_ip" {}
variable "master_ips" {}
variable "worker_ips" {}
