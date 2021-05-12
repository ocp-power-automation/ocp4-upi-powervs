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

locals {
  api_servers        = var.bootstrap_count == 0 ? var.master_ips : concat([var.bootstrap_ip], var.master_ips)
  api_servers_count  = var.bootstrap_count + var.master_count
  apps_servers       = var.worker_count == 0 ? var.master_ips : var.worker_ips
  apps_servers_count = var.worker_count == 0 ? var.master_count : var.worker_count
}

resource "ibm_is_lb" "load_balancer" {
  name            = "${var.cluster_id}-loadbalancer"
  subnets         = [var.vpc_subnet_id]
  security_groups = [ibm_is_security_group.ocp_security_group.id]
}

# machine config listener and backend pool
resource "ibm_is_lb_listener" "machine_config_listener" {
  lb           = ibm_is_lb.load_balancer.id
  port         = 22623
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.machine_config_pool.id
}
resource "ibm_is_lb_pool" "machine_config_pool" {
  depends_on = [ibm_is_lb.load_balancer]

  name           = "machine-config-server"
  lb             = ibm_is_lb.load_balancer.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "machine_config_member" {
  depends_on = [ibm_is_lb_listener.machine_config_listener]
  count      = local.api_servers_count

  lb             = ibm_is_lb.load_balancer.id
  pool           = ibm_is_lb_pool.machine_config_pool.id
  port           = 22623
  target_address = local.api_servers[count.index]
}


# api listener and backend pool
resource "ibm_is_lb_listener" "api_listener" {
  lb           = ibm_is_lb.load_balancer.id
  port         = 6443
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.api_pool.id
}
resource "ibm_is_lb_pool" "api_pool" {
  depends_on = [ibm_is_lb.load_balancer]

  name           = "openshift-api-server"
  lb             = ibm_is_lb.load_balancer.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "api_member" {
  depends_on = [ibm_is_lb_listener.api_listener, ibm_is_lb_pool_member.machine_config_member]
  count      = local.api_servers_count

  lb             = ibm_is_lb.load_balancer.id
  pool           = ibm_is_lb_pool.api_pool.id
  port           = 6443
  target_address = local.api_servers[count.index]
}


# ingress http listener and backend pool
resource "ibm_is_lb_listener" "ingress_http_listener" {
  lb           = ibm_is_lb.load_balancer.id
  port         = 80
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.ingress_http_pool.id
}
resource "ibm_is_lb_pool" "ingress_http_pool" {
  depends_on = [ibm_is_lb.load_balancer]

  name           = "ingress-http"
  lb             = ibm_is_lb.load_balancer.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "ingress_http_member" {
  depends_on = [ibm_is_lb_listener.ingress_http_listener, ibm_is_lb_pool_member.api_member]
  count      = local.apps_servers_count

  lb             = ibm_is_lb.load_balancer.id
  pool           = ibm_is_lb_pool.ingress_http_pool.id
  port           = 80
  target_address = local.apps_servers[count.index]
}


# ingress https listener and backend pool
resource "ibm_is_lb_listener" "ingress_https_listener" {
  lb           = ibm_is_lb.load_balancer.id
  port         = 443
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.ingress_https_pool.id
}
resource "ibm_is_lb_pool" "ingress_https_pool" {
  depends_on = [ibm_is_lb.load_balancer]

  name           = "ingress-https"
  lb             = ibm_is_lb.load_balancer.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "ingress_https_member" {
  depends_on = [ibm_is_lb_listener.ingress_https_listener, ibm_is_lb_pool_member.ingress_http_member]
  count      = local.apps_servers_count

  lb             = ibm_is_lb.load_balancer.id
  pool           = ibm_is_lb_pool.ingress_https_pool.id
  port           = 443
  target_address = local.apps_servers[count.index]
}
