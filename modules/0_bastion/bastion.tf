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

data "ibm_pi_image" "bastion" {
    pi_image_name           = var.rhel_image_name
    pi_cloud_instance_id    = var.service_instance_id
}

data "ibm_pi_network" "network" {
    pi_network_name         = var.network_name
    pi_cloud_instance_id    = var.service_instance_id
}

## Fix for Terraform CRASH.. always create new public network
resource "ibm_pi_network" "public_network" {
    count               = !var.custom_bastion ? 1 : 0

    pi_network_name           = "${var.cluster_id}-pub-net"
    pi_cloud_instance_id      = var.service_instance_id
    pi_network_type           = "pub-vlan"
}

data "ibm_pi_network" "public_network" {
    depends_on              = [ibm_pi_network.public_network]
    pi_network_name         = var.custom_bastion ? var.custom_bastion_public_network : "${var.cluster_id}-pub-net"
    pi_cloud_instance_id    = var.service_instance_id
}

## Use this when public network issues are fixed.
#data "ibm_pi_public_network" "public_network" {
#    depends_on              = ["ibm_pi_network.public_network"]
#    pi_cloud_instance_id    = var.service_instance_id
#}

resource "ibm_pi_key" "key" {
    count               = !var.custom_bastion ? 1 : 0

    pi_cloud_instance_id = var.service_instance_id
    pi_key_name          = "${var.cluster_id}-keypair"
    pi_ssh_key           = var.public_key
}

resource "ibm_pi_volume" "volume" {
    count               = var.storage_type == "nfs" && !var.custom_bastion ? 1 : 0

    pi_volume_size       = var.volume_size
    pi_volume_name       = "${var.cluster_id}-${var.storage_type}-volume"
    pi_volume_type       = var.volume_type
    pi_volume_shareable  = var.volume_shareable
    pi_cloud_instance_id = var.service_instance_id
}

data "ibm_pi_volume" "volume" {
    count               = var.custom_bastion && var.custom_bastion_volume != "" ? 1 : 0

    pi_volume_name          = var.custom_bastion_volume
    pi_cloud_instance_id    = var.service_instance_id
}

resource "ibm_pi_instance" "bastion" {
    count               = !var.custom_bastion ? 1 : 0

    pi_memory               = var.bastion["memory"]
    pi_processors           = var.bastion["processors"]
    pi_instance_name        = "${var.cluster_id}-bastion"
    pi_proc_type            = var.processor_type
    pi_image_id             = data.ibm_pi_image.bastion.id
    pi_network_ids          = [data.ibm_pi_network.public_network.id, data.ibm_pi_network.network.id]
    pi_key_pair_name        = ibm_pi_key.key[0].key_id
    pi_sys_type             = var.system_type
    pi_cloud_instance_id    = var.service_instance_id
    pi_volume_ids           = var.storage_type == "nfs" ? ibm_pi_volume.volume.*.volume_id : null
    pi_health_status        = "WARNING"
    # Fix for default route on public interface
    pi_user_data            = base64encode(
                                templatefile(
                                    "${path.module}/templates/fix_default_route.sh",
                                    {pub_gateway = data.ibm_pi_network.public_network.gateway}
                                )
                              )
    provisioner "remote-exec" {
        connection {
            type        = "ssh"
            user        = var.rhel_username
            host        = compact(self.addresses.*.external_ip)[0]
            private_key = var.private_key
            agent       = var.ssh_agent
            timeout     = "15m"
        }
        when        = destroy
        on_failure  = continue
        inline = [
            "sudo subscription-manager unregister",
            "sudo subscription-manager remove --all",
        ]
    }
}

data "ibm_pi_instance_ip" "bastion_ip" {
    depends_on              = [ibm_pi_instance.bastion]
    pi_instance_name        = var.custom_bastion ? var.custom_bastion_name : ibm_pi_instance.bastion[0].pi_instance_name
    pi_network_name         = data.ibm_pi_network.network.name
    pi_cloud_instance_id    = var.service_instance_id
}

data "ibm_pi_instance_ip" "bastion_public_ip" {
    depends_on              = [ibm_pi_instance.bastion]
    pi_instance_name        = var.custom_bastion ? var.custom_bastion_name : ibm_pi_instance.bastion[0].pi_instance_name
    pi_network_name         = data.ibm_pi_network.public_network.name
    pi_cloud_instance_id    = var.service_instance_id
}
