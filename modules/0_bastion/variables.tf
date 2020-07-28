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

variable "cluster_id" {}

variable "custom_bastion" {}
variable "custom_bastion_name" {}
variable "custom_bastion_public_network" {}
variable "custom_bastion_volume" {}

variable "bastion" {
    # only one node is supported
    default = {
        memory      = "4"
        image_name  = "RHEL82"
        processors  = "1"
    }
}

variable "service_instance_id" {}
variable "rhel_image_name" {}

variable "private_key" {}
variable "public_key" {}

variable "processor_type" {}
variable "system_type" {}
variable "network_name" {}

variable "rhel_username" {}
variable "ssh_agent" {}

variable "rhel_subscription_username" {}
variable "rhel_subscription_password" {}

variable "storage_type" {}
variable "volume_type" {}
variable "volume_size" {}
variable "volume_shareable" {}
