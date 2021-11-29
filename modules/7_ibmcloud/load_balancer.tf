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

################################################################
##### Network topology requirements
##### Ref: https://docs.openshift.com/container-platform/4.7/installing/installing_platform_agnostic/installing-platform-agnostic.html
################################################################

locals {
  api_servers        = var.bootstrap_count == 0 ? var.master_ips : concat([var.bootstrap_ip], var.master_ips)
  api_servers_count  = var.bootstrap_count + var.master_count
  apps_servers       = var.worker_count == 0 ? var.master_ips : var.worker_ips
  apps_servers_count = var.worker_count == 0 ? var.master_count : var.worker_count
}

resource "ibm_is_lb" "load_balancer_internal" {
  name            = "${var.name_prefix}internal-loadbalancer"
  subnets         = [var.vpc_subnet_id]
  security_groups = [ibm_is_security_group.ocp_security_group.id]
  type            = "private"
}

resource "ibm_is_lb" "load_balancer_external" {
  name            = "${var.name_prefix}external-loadbalancer"
  subnets         = [var.vpc_subnet_id]
  security_groups = [ibm_is_security_group.ocp_security_group.id]
  type            = "public"
}

# machine config listener and backend pool
resource "ibm_is_lb_listener" "machine_config_listener" {
  lb           = ibm_is_lb.load_balancer_internal.id
  port         = 22623
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.machine_config_pool.id
}
resource "ibm_is_lb_pool" "machine_config_pool" {
  depends_on = [ibm_is_lb.load_balancer_internal]

  name           = "machine-config-server"
  lb             = ibm_is_lb.load_balancer_internal.id
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

  lb             = ibm_is_lb.load_balancer_internal.id
  pool           = ibm_is_lb_pool.machine_config_pool.id
  port           = 22623
  target_address = local.api_servers[count.index]
}

# api listener and backend pool (internal)
resource "ibm_is_lb_listener" "api_listener_internal" {
  lb           = ibm_is_lb.load_balancer_internal.id
  port         = 6443
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.api_pool_internal.id
}
resource "ibm_is_lb_pool" "api_pool_internal" {
  depends_on = [ibm_is_lb.load_balancer_internal]

  name           = "openshift-api-server"
  lb             = ibm_is_lb.load_balancer_internal.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "api_member_internal" {
  depends_on = [ibm_is_lb_listener.api_listener_internal, ibm_is_lb_pool_member.machine_config_member]
  count      = local.api_servers_count

  lb             = ibm_is_lb.load_balancer_internal.id
  pool           = ibm_is_lb_pool.api_pool_internal.id
  port           = 6443
  target_address = local.api_servers[count.index]
}

# api listener and backend pool (external)
resource "ibm_is_lb_listener" "api_listener_external" {
  lb           = ibm_is_lb.load_balancer_external.id
  port         = 6443
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.api_pool_external.id
}
resource "ibm_is_lb_pool" "api_pool_external" {
  depends_on = [ibm_is_lb.load_balancer_external]

  name           = "openshift-api-server"
  lb             = ibm_is_lb.load_balancer_external.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "api_member_external" {
  depends_on = [ibm_is_lb_listener.api_listener_external, ibm_is_lb_pool_member.machine_config_member]
  count      = local.api_servers_count

  lb             = ibm_is_lb.load_balancer_external.id
  pool           = ibm_is_lb_pool.api_pool_external.id
  port           = 6443
  target_address = local.api_servers[count.index]
}

# ingress http listener and backend pool (internal)
resource "ibm_is_lb_listener" "ingress_http_listener_internal" {
  lb           = ibm_is_lb.load_balancer_internal.id
  port         = 80
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.ingress_http_pool_internal.id
}
resource "ibm_is_lb_pool" "ingress_http_pool_internal" {
  depends_on = [ibm_is_lb.load_balancer_internal]

  name           = "ingress-http"
  lb             = ibm_is_lb.load_balancer_internal.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "ingress_http_member_internal" {
  depends_on = [ibm_is_lb_listener.ingress_http_listener_internal, ibm_is_lb_pool_member.api_member_internal]
  count      = local.apps_servers_count

  lb             = ibm_is_lb.load_balancer_internal.id
  pool           = ibm_is_lb_pool.ingress_http_pool_internal.id
  port           = 80
  target_address = local.apps_servers[count.index]
}

# ingress http listener and backend pool (external)
resource "ibm_is_lb_listener" "ingress_http_listener_external" {
  lb           = ibm_is_lb.load_balancer_external.id
  port         = 80
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.ingress_http_pool_external.id
}
resource "ibm_is_lb_pool" "ingress_http_pool_external" {
  depends_on = [ibm_is_lb.load_balancer_external]

  name           = "ingress-http"
  lb             = ibm_is_lb.load_balancer_external.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "ingress_http_member_external" {
  depends_on = [ibm_is_lb_listener.ingress_http_listener_external, ibm_is_lb_pool_member.api_member_external]
  count      = local.apps_servers_count

  lb             = ibm_is_lb.load_balancer_external.id
  pool           = ibm_is_lb_pool.ingress_http_pool_external.id
  port           = 80
  target_address = local.apps_servers[count.index]
}

# ingress https listener and backend pool (internal)
resource "ibm_is_lb_listener" "ingress_https_listener_internal" {
  lb           = ibm_is_lb.load_balancer_internal.id
  port         = 443
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.ingress_https_pool_internal.id
}
resource "ibm_is_lb_pool" "ingress_https_pool_internal" {
  depends_on = [ibm_is_lb.load_balancer_internal]

  name           = "ingress-https"
  lb             = ibm_is_lb.load_balancer_internal.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "ingress_https_member_internal" {
  depends_on = [ibm_is_lb_listener.ingress_https_listener_internal, ibm_is_lb_pool_member.ingress_http_member_internal]
  count      = local.apps_servers_count

  lb             = ibm_is_lb.load_balancer_internal.id
  pool           = ibm_is_lb_pool.ingress_https_pool_internal.id
  port           = 443
  target_address = local.apps_servers[count.index]
}

# ingress https listener and backend pool (external)
resource "ibm_is_lb_listener" "ingress_https_listener_external" {
  lb           = ibm_is_lb.load_balancer_external.id
  port         = 443
  protocol     = "tcp"
  default_pool = ibm_is_lb_pool.ingress_https_pool_external.id
}
resource "ibm_is_lb_pool" "ingress_https_pool_external" {
  depends_on = [ibm_is_lb.load_balancer_external]

  name           = "ingress-https"
  lb             = ibm_is_lb.load_balancer_external.id
  algorithm      = "round_robin"
  protocol       = "tcp"
  health_delay   = 60
  health_retries = 5
  health_timeout = 30
  health_type    = "tcp"
}
resource "ibm_is_lb_pool_member" "ingress_https_member_external" {
  depends_on = [ibm_is_lb_listener.ingress_https_listener_external, ibm_is_lb_pool_member.ingress_http_member_external]
  count      = local.apps_servers_count

  lb             = ibm_is_lb.load_balancer_external.id
  pool           = ibm_is_lb_pool.ingress_https_pool_external.id
  port           = 443
  target_address = local.apps_servers[count.index]
}
