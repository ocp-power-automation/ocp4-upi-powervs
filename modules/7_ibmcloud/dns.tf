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

#####################################
##### DNS 
#####################################

data "ibm_cis_domain" "domain" {
  cis_id = var.ibm_cloud_cis_crn
  domain = var.cluster_domain
}

resource "ibm_cis_dns_record" "bastion" {
  count     = var.bastion_count
  cis_id    = var.ibm_cloud_cis_crn
  content   = var.bastion_ip[count.index]
  domain_id = data.ibm_cis_domain.domain.id
  name      = "${var.name_prefix}bastion-${count.index}.${var.cluster_id}.${var.cluster_domain}"
  ttl       = 900
  type      = "A"
}
resource "ibm_cis_dns_record" "registry" {
  cis_id    = var.ibm_cloud_cis_crn
  content   = var.bastion_vip != "" ? var.bastion_vip : var.bastion_ip[0]
  domain_id = data.ibm_cis_domain.domain.id
  name      = "registry.${var.cluster_id}.${var.cluster_domain}"
  ttl       = 900
  type      = "A"
}
resource "ibm_cis_dns_record" "bootstrap" {
  count     = var.bootstrap_count
  cis_id    = var.ibm_cloud_cis_crn
  content   = var.bootstrap_ip
  domain_id = data.ibm_cis_domain.domain.id
  name      = "${var.node_prefix}bootstrap.${var.cluster_id}.${var.cluster_domain}"
  ttl       = 900
  type      = "A"
}
resource "ibm_cis_dns_record" "master" {
  count     = var.master_count
  cis_id    = var.ibm_cloud_cis_crn
  content   = var.master_ips[count.index]
  domain_id = data.ibm_cis_domain.domain.id
  name      = "${var.node_prefix}master-${count.index}.${var.cluster_id}.${var.cluster_domain}"
  ttl       = 900
  type      = "A"
}
resource "ibm_cis_dns_record" "worker" {
  count     = var.worker_count
  cis_id    = var.ibm_cloud_cis_crn
  content   = var.worker_ips[count.index]
  domain_id = data.ibm_cis_domain.domain.id
  name      = "${var.node_prefix}worker-${count.index}.${var.cluster_id}.${var.cluster_domain}"
  ttl       = 900
  type      = "A"
}

#####################################
##### Kubernetes 
#####################################
resource "ibm_cis_dns_record" "api" {
  cis_id    = var.ibm_cloud_cis_crn
  content   = ibm_is_lb.load_balancer_external.hostname
  domain_id = data.ibm_cis_domain.domain.id
  name      = "api.${var.cluster_id}.${var.cluster_domain}"
  ttl       = 900
  type      = "CNAME"
}
resource "ibm_cis_dns_record" "api-int" {
  cis_id    = var.ibm_cloud_cis_crn
  content   = ibm_is_lb.load_balancer_internal.hostname
  domain_id = data.ibm_cis_domain.domain.id
  name      = "api-int.${var.cluster_id}.${var.cluster_domain}"
  ttl       = 900
  type      = "CNAME"
}
resource "ibm_cis_dns_record" "apps" {
  cis_id    = var.ibm_cloud_cis_crn
  content   = ibm_is_lb.load_balancer_external.hostname
  domain_id = data.ibm_cis_domain.domain.id
  name      = "*.apps.${var.cluster_id}.${var.cluster_domain}"
  ttl       = 900
  type      = "CNAME"
}
