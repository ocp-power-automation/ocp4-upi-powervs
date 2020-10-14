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

variable "cluster_domain" {}
variable "cluster_id" {}
variable "bastion" {}

variable "service_instance_id" {}
variable "rhel_image_name" {}

variable "private_key" {}
variable "public_key" {}

variable "processor_type" {}
variable "system_type" {}
variable "network_name" {}
variable "network_dns" {}

variable "rhel_username" {}
variable "ssh_agent" {}

variable "rhel_subscription_username" {}
variable "rhel_subscription_password" {}

variable "rhel_smt" {}

variable "storage_type" {}
variable "volume_type" {}
variable "volume_size" {}
variable "volume_shareable" {}

variable "setup_squid_proxy" {}
variable "proxy" {}
