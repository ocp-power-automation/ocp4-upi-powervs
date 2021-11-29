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

data "ibm_dns_domain" "domain" {
  name = var.cluster_domain
}

resource "ibm_dns_record" "bastion" {
  count              = var.bastion_count
  data               = var.bastion_ip[count.index]
  domain_id          = data.ibm_dns_domain.domain.id
  host               = "${var.name_prefix}bastion-${count.index}.${var.cluster_id}"
  responsible_person = "root.${var.cluster_domain}."
  ttl                = 900
  type               = "a"
}
resource "ibm_dns_record" "registry" {
  data               = var.bastion_vip != "" ? var.bastion_vip : var.bastion_ip[0]
  domain_id          = data.ibm_dns_domain.domain.id
  host               = "registry.${var.cluster_id}"
  responsible_person = "root.${var.cluster_domain}."
  ttl                = 900
  type               = "a"
}
resource "ibm_dns_record" "bootstrap" {
  count              = var.bootstrap_count
  data               = var.bootstrap_ip
  domain_id          = data.ibm_dns_domain.domain.id
  host               = "${var.node_prefix}bootstrap.${var.cluster_id}"
  responsible_person = "root.${var.cluster_domain}."
  ttl                = 900
  type               = "a"
}
resource "ibm_dns_record" "master" {
  count              = var.master_count
  data               = var.master_ips[count.index]
  domain_id          = data.ibm_dns_domain.domain.id
  host               = "${var.node_prefix}master-${count.index}.${var.cluster_id}"
  responsible_person = "root.${var.cluster_domain}."
  ttl                = 900
  type               = "a"
}
resource "ibm_dns_record" "worker" {
  count              = var.worker_count
  data               = var.worker_ips[count.index]
  domain_id          = data.ibm_dns_domain.domain.id
  host               = "${var.node_prefix}worker-${count.index}.${var.cluster_id}"
  responsible_person = "root.${var.cluster_domain}."
  ttl                = 900
  type               = "a"
}
resource "ibm_dns_record" "api" {
  data               = "${ibm_is_lb.load_balancer_external.hostname}."
  domain_id          = data.ibm_dns_domain.domain.id
  host               = "api.${var.cluster_id}"
  responsible_person = "root.${var.cluster_domain}."
  ttl                = 900
  type               = "cname"
}
resource "ibm_dns_record" "api-int" {
  data               = "${ibm_is_lb.load_balancer_internal.hostname}."
  domain_id          = data.ibm_dns_domain.domain.id
  host               = "api-int.${var.cluster_id}"
  responsible_person = "root.${var.cluster_domain}."
  ttl                = 900
  type               = "cname"
}
resource "ibm_dns_record" "apps" {
  data               = "${ibm_is_lb.load_balancer_external.hostname}."
  domain_id          = data.ibm_dns_domain.domain.id
  host               = "*.apps.${var.cluster_id}"
  responsible_person = "root.${var.cluster_domain}."
  ttl                = 900
  type               = "cname"
}
