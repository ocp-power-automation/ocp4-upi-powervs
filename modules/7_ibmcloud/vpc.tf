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

locals {
  create_vpc        = var.vpc_name == ""
  create_subnet     = var.vpc_name == "" || var.vpc_subnet_name == ""
  vpc_id            = local.create_vpc ? ibm_is_vpc.vpc[0].id : data.ibm_is_vpc.vpc[0].id
  vpc_subnet_id     = local.create_subnet ? ibm_is_subnet.subnet[0].id : data.ibm_is_subnet.subnet[0].id
  vpc_subnet_cidr   = local.create_subnet ? ibm_is_subnet.subnet[0].ipv4_cidr_block : data.ibm_is_subnet.subnet[0].ipv4_cidr_block
  resource_group_id = data.ibm_resource_group.group.id
}

data "ibm_is_vpc" "vpc" {
  count = local.create_vpc ? 0 : 1

  name = var.vpc_name
}

data "ibm_is_subnet" "subnet" {
  count = local.create_subnet ? 0 : 1

  name = var.vpc_subnet_name
}

data "ibm_resource_group" "group" {
  name = var.ibm_cloud_resource_group
}

resource "ibm_is_vpc" "vpc" {
  count = local.create_vpc ? 1 : 0

  name           = "${var.cluster_id}-vpc"
  resource_group = local.resource_group_id
  tags           = [var.cluster_id, "powervs-openshift"]
}

resource "ibm_is_subnet" "subnet" {
  count = local.create_subnet ? 1 : 0

  name                     = "${var.cluster_id}-subnet"
  vpc                      = local.create_vpc ? ibm_is_vpc.vpc[0].id : data.ibm_is_vpc.vpc[0].id
  resource_group           = local.resource_group_id
  total_ipv4_address_count = 256
  zone                     = "${var.vpc_region}-1"
  tags                     = [var.cluster_id, "powervs-openshift"]
}
