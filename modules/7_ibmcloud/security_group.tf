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

locals {
  tcp_ports = [22623, 6443, 443, 80]
}
data "ibm_is_vpc" "vpc" {
  name = var.vpc_name
}

resource "ibm_is_security_group" "ocp_security_group" {
  name = "${var.name_prefix}ocp-sec-group"
  vpc  = data.ibm_is_vpc.vpc.id
}

resource "ibm_is_security_group_rule" "inbound_ports" {
  count     = length(local.tcp_ports)
  group     = ibm_is_security_group.ocp_security_group.id
  direction = "inbound"
  tcp {
    port_min = local.tcp_ports[count.index]
    port_max = local.tcp_ports[count.index]
  }
}

resource "ibm_is_security_group_rule" "outbound_any" {
  group     = ibm_is_security_group.ocp_security_group.id
  direction = "outbound"
}
