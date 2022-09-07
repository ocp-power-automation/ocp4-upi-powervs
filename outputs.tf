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

output "cluster_id" {
  value = local.cluster_id
}

output "name_prefix" {
  value = local.name_prefix
}

output "bastion_private_vip" {
  value = module.prepare.bastion_vip == "" ? null : module.prepare.bastion_vip
}

output "bastion_external_vip" {
  value = module.install.bastion_external_vip == "" ? null : module.install.bastion_external_vip
}

output "bastion_private_ip" {
  value = join(", ", module.prepare.bastion_ip)
}

output "bastion_public_ip" {
  value = join(", ", module.prepare.bastion_public_ip)
}

output "bastion_ssh_command" {
  value = "ssh -i ${var.private_key_file} ${var.rhel_username}@${module.install.bastion_external_vip == "" ? module.prepare.bastion_public_ip[0] : module.install.bastion_external_vip}"
}

output "bootstrap_ip" {
  value = module.nodes.bootstrap_ip
}

output "master_ips" {
  value = module.nodes.master_ips
}

output "worker_ips" {
  value = module.nodes.worker_ips
}

output "dns_entries" {
  value = var.use_ibm_cloud_services || var.cluster_domain == "nip.io" || var.cluster_domain == "xip.io" || var.cluster_domain == "sslip.io" ? null : <<-EOF

api.${local.cluster_id}.${var.cluster_domain}.  IN  A  ${module.install.bastion_external_vip == "" ? module.prepare.bastion_public_ip[0] : module.install.bastion_external_vip}
*.apps.${local.cluster_id}.${var.cluster_domain}.  IN  A  ${module.install.bastion_external_vip == "" ? module.prepare.bastion_public_ip[0] : module.install.bastion_external_vip}
EOF
}

output "etc_hosts_entries" {
  value = var.use_ibm_cloud_services || var.cluster_domain == "nip.io" || var.cluster_domain == "xip.io" || var.cluster_domain == "sslip.io" ? null : <<-EOF

${module.install.bastion_external_vip == "" ? module.prepare.bastion_public_ip[0] : module.install.bastion_external_vip} api.${local.cluster_id}.${var.cluster_domain} console-openshift-console.apps.${local.cluster_id}.${var.cluster_domain} integrated-oauth-server-openshift-authentication.apps.${local.cluster_id}.${var.cluster_domain} oauth-openshift.apps.${local.cluster_id}.${var.cluster_domain} prometheus-k8s-openshift-monitoring.apps.${local.cluster_id}.${var.cluster_domain} grafana-openshift-monitoring.apps.${local.cluster_id}.${var.cluster_domain} example.apps.${local.cluster_id}.${var.cluster_domain}
EOF
}

output "oc_server_url" {
  value = module.install.oc_server_url
}

output "web_console_url" {
  value = module.install.web_console_url
}

output "storageclass_name" {
  value = "nfs-storage-provisioner"
}

output "install_status" {
  value = module.install.install_status
}

output "cluster_authentication_details" {
  value = "Cluster authentication details are available in ${join(", ", module.prepare.bastion_public_ip)} under ~/openstack-upi/auth"
}

output "load_balancer_hostname" {
  value = var.use_ibm_cloud_services ? module.ibmcloud[0].load_balancer_hostname : null
}
