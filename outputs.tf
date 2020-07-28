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

output "bastion_private_ip" {
    value = module.bastion.bastion_ip
}

output "bastion_public_ip" {
    value = module.bastion.bastion_public_ip
}

output "bastion_ssh_command" {
    value = "ssh ${var.rhel_username}@${module.bastion.bastion_public_ip}"
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

output "etc_hosts_entries" {
    value = <<-EOF

${module.prepare.bastion_public_ip} api.${local.cluster_id}.${var.cluster_domain} console-openshift-console.apps.${local.cluster_id}.${var.cluster_domain} integrated-oauth-server-openshift-authentication.apps.${local.cluster_id}.${var.cluster_domain} oauth-openshift.apps.${local.cluster_id}.${var.cluster_domain} prometheus-k8s-openshift-monitoring.apps.${local.cluster_id}.${var.cluster_domain} grafana-openshift-monitoring.apps.${local.cluster_id}.${var.cluster_domain} example.apps.${local.cluster_id}.${var.cluster_domain}
EOF
}

output "oc_server_url" {
    value = "https://api.${local.cluster_id}.${var.cluster_domain}:6443/"
}

output "web_console_url" {
    value = "https://console-openshift-console.apps.${local.cluster_id}.${var.cluster_domain}"
}

output "storageclass_name" {
    value = "nfs-storage-provisioner"
}

output "install_status" {
    value = module.install.install_status
}

