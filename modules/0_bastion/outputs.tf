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

output "bastion_ip" {
    depends_on = [data.ibm_pi_instance_ip.bastion_ip]
    value = data.ibm_pi_instance_ip.bastion_ip.ip
}

output "bastion_public_ip" {
    depends_on = [data.ibm_pi_instance_ip.bastion_public_ip]
    value = data.ibm_pi_instance_ip.bastion_public_ip.external_ip
}

output "bastion_volume_size" {
    depends_on = [data.ibm_pi_volume.volume]
    value = var.custom_bastion && var.custom_bastion_volume != "" ? data.ibm_pi_volume.volume[0].size : var.volume_size
}
