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

output "bootstrap_ip" {
  value = join("", data.ibm_pi_instance_ip.bootstrap_ip.*.ip)
}

output "bootstrap_mac" {
  value = join("", data.ibm_pi_instance_ip.bootstrap_ip.*.macaddress)
}

output "master_ips" {
  value = data.ibm_pi_instance_ip.master_ip.*.ip
}

output "master_macs" {
  value = data.ibm_pi_instance_ip.master_ip.*.macaddress
}

output "worker_ips" {
  value = data.ibm_pi_instance_ip.worker_ip.*.ip
}

output "worker_macs" {
  value = data.ibm_pi_instance_ip.worker_ip.*.macaddress
}

output "master_ids" {
  value = ibm_pi_instance.master.*.instance_id
}

output "worker_ids" {
  value = ibm_pi_instance.worker.*.instance_id
}

output "cluster_domain" {
  value = local.cluster_domain
}
