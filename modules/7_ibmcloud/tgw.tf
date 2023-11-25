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
# ©Copyright IBM Corp. 2023
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

data "ibm_tg_gateway" "transit_gateway" {
  count = local.create_tgw ? 0 : 1

  name = var.ibm_cloud_tgw
}

resource "ibm_tg_gateway" "transit_gateway" {
  count = local.create_tgw ? 1 : 0

  name           = "${var.cluster_id}-tgw"
  location       = var.vpc_region
  global         = true
  resource_group = local.resource_group_id
}

resource "ibm_tg_connection" "tg_connection_vpc" {
  count = local.create_vpc || local.create_tgw ? 1 : 0

  gateway      = local.tgw_id
  network_type = "vpc"
  name         = "${var.cluster_id}-conn-vpc"
  network_id   = local.vpc_crn
}

resource "ibm_tg_connection" "tg_connection_powervs" {
  count = var.is_new_cloud_connection || local.create_tgw ? 1 : 0

  gateway      = local.tgw_id
  network_type = var.is_per ? "power_virtual_server" : "directlink"
  name         = "${var.cluster_id}-conn-powervs"
  network_id   = var.is_per ? var.ibm_cloud_tgw_net : data.ibm_dl_gateway.dl[0].crn
}

# If power workspace is given not required
data "ibm_dl_gateway" "dl" {
  count      = var.is_per ? 0 : 1
  depends_on = [var.ibm_cloud_tgw_net]
  name       = var.ibm_cloud_tgw_net
}

locals {
  create_tgw = var.ibm_cloud_tgw == "" ? true : false
  tgw_id     = local.create_tgw ? resource.ibm_tg_gateway.transit_gateway[0].id : data.ibm_tg_gateway.transit_gateway[0].id
}
