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


variable "service_instance_id" {}

variable "processor_type" {}
variable "system_type" {}
variable "network_name" {}
variable "rhcos_image_name" {}

variable "bastion_ip" {}
variable "cluster_domain" {}
variable "cluster_id" {}
variable "name_prefix" {}
variable "node_prefix" {}
variable "bootstrap" {}
variable "master" {}
variable "worker" {}

variable "volume_shareable" {}

variable "bastion_public_ip" {}
variable "bastion_external_vip" {}
variable "rhel_username" {}
variable "private_key" {}
variable "ssh_agent" {}

variable "rhcos_import_image" {}
variable "rhcos_import_bucket_region" {}
variable "rhcos_import_image_filename" {}
variable "rhcos_import_image_storage_type" {}
