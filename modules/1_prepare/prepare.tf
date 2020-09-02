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
    proxy = {
        server    = lookup(var.proxy, "server", ""),
        port        = lookup(var.proxy, "port", "3128"),
        user        = lookup(var.proxy, "user", ""),
        password    = lookup(var.proxy, "password", "")
        user_pass   = lookup(var.proxy, "user", "") == "" ? "" : "${lookup(var.proxy, "user", "")}:${lookup(var.proxy, "password", "")}@"
        no_proxy    = "127.0.0.1,localhost,.${var.cluster_id}.${var.cluster_domain}"
    }
}

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
    pi_network_name           = "${var.cluster_id}-pub-net"
    pi_cloud_instance_id      = var.service_instance_id
    pi_network_type           = "pub-vlan"
}

## Use this when public network issues are fixed.
#data "ibm_pi_public_network" "public_network" {
#    depends_on              = ["ibm_pi_network.public_network"]
#    pi_cloud_instance_id    = var.service_instance_id
#}

resource "ibm_pi_key" "key" {
    pi_cloud_instance_id = var.service_instance_id
    pi_key_name          = "${var.cluster_id}-keypair"
    pi_ssh_key           = var.public_key
}

resource "ibm_pi_volume" "volume" {
    count               = var.storage_type == "nfs" ? 1 : 0

    pi_volume_size       = var.volume_size
    pi_volume_name       = "${var.cluster_id}-${var.storage_type}-volume"
    pi_volume_type       = var.volume_type
    pi_volume_shareable  = var.volume_shareable
    pi_cloud_instance_id = var.service_instance_id
}

resource "ibm_pi_instance" "bastion" {
    pi_memory               = var.bastion["memory"]
    pi_processors           = var.bastion["processors"]
    pi_instance_name        = "${var.cluster_id}-bastion"
    pi_proc_type            = var.processor_type
    pi_image_id             = data.ibm_pi_image.bastion.id
    pi_network_ids          = [ibm_pi_network.public_network.network_id, data.ibm_pi_network.network.id]
    pi_key_pair_name        = ibm_pi_key.key.key_id
    pi_sys_type             = var.system_type
    pi_cloud_instance_id    = var.service_instance_id
    pi_volume_ids           = var.storage_type == "nfs" ? ibm_pi_volume.volume.*.volume_id : null
    # Fix for default route on public interface
    pi_user_data            = base64encode(
                                templatefile(
                                    "${path.module}/templates/fix_default_route.sh",
                                    {pub_gateway = cidrhost(ibm_pi_network.public_network.pi_cidr,1)}
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
    pi_instance_name        = ibm_pi_instance.bastion.pi_instance_name
    pi_network_name         = data.ibm_pi_network.network.name
    pi_cloud_instance_id    = var.service_instance_id
}

data "ibm_pi_instance_ip" "bastion_public_ip" {
    depends_on              = [ibm_pi_instance.bastion]
    pi_instance_name        = ibm_pi_instance.bastion.pi_instance_name
    pi_network_name         = ibm_pi_network.public_network.pi_network_name
    pi_cloud_instance_id    = var.service_instance_id
}

resource "null_resource" "bastion_init" {
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = data.ibm_pi_instance_ip.bastion_ip.ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = data.ibm_pi_instance_ip.bastion_public_ip.external_ip
    }
    provisioner "remote-exec" {
        inline = [
            "whoami"
        ]
    }
    provisioner "file" {
        content = var.private_key
        destination = "~/.ssh/id_rsa"
    }
    provisioner "file" {
        content = var.public_key
        destination = "~/.ssh/id_rsa.pub"
    }
    provisioner "remote-exec" {
        inline = [
            "sudo chmod 600 ~/.ssh/id_rsa*",
            "sudo sed -i.bak -e 's/^ - set_hostname/# - set_hostname/' -e 's/^ - update_hostname/# - update_hostname/' /etc/cloud/cloud.cfg",
            "sudo hostnamectl set-hostname --static ${lower(var.cluster_id)}-bastion.${var.cluster_domain}",
            "echo 'HOSTNAME=${lower(var.cluster_id)}-bastion.${var.cluster_domain}' | sudo tee -a /etc/sysconfig/network > /dev/null",
            "sudo hostname -F /etc/hostname",
            "echo 'vm.max_map_count = 262144' | sudo tee --append /etc/sysctl.conf > /dev/null",
            # Set SMT to user specified value; Should not fail for invalid values.
            "sudo ppc64_cpu --smt=${var.rhel_smt} | true",
        ]
    }
}

resource "null_resource" "setup_proxy_info" {
    depends_on  = [null_resource.bastion_init]
    count       = !var.setup_squid_proxy && local.proxy.server != "" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = data.ibm_pi_instance_ip.bastion_ip.ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = data.ibm_pi_instance_ip.bastion_public_ip.external_ip
    }
    # Setup proxy
    provisioner "remote-exec" {
        inline = [<<EOF

echo "Setting up proxy details..."

# System
set http_proxy="http://${local.proxy.user_pass}${local.proxy.server}:${local.proxy.port}"
set https_proxy="http://${local.proxy.user_pass}${local.proxy.server}:${local.proxy.port}"
set no_proxy="${local.proxy.no_proxy}"
echo "export http_proxy=\"http://${local.proxy.user_pass}${local.proxy.server}:${local.proxy.port}\"" | sudo tee /etc/profile.d/http_proxy.sh > /dev/null
echo "export https_proxy=\"http://${local.proxy.user_pass}${local.proxy.server}:${local.proxy.port}\"" | sudo tee -a /etc/profile.d/http_proxy.sh > /dev/null
echo "export no_proxy=\"${local.proxy.no_proxy}\"" | sudo tee -a /etc/profile.d/http_proxy.sh > /dev/null

# RHSM
sudo sed -i -e 's/^proxy_hostname =.*/proxy_hostname = ${local.proxy.server}/' /etc/rhsm/rhsm.conf
sudo sed -i -e 's/^proxy_port =.*/proxy_port = ${local.proxy.port}/' /etc/rhsm/rhsm.conf
sudo sed -i -e 's/^proxy_user =.*/proxy_user = ${local.proxy.user}/' /etc/rhsm/rhsm.conf
sudo sed -i -e 's/^proxy_password =.*/proxy_password = ${local.proxy.password}/' /etc/rhsm/rhsm.conf

# YUM/DNF
# Incase /etc/yum.conf is a symlink to /etc/dnf/dnf.conf we try to update the original file
yum_dnf_conf=$(readlink -f -q /etc/yum.conf)
sudo sed -i -e '/^proxy.*/d' $yum_dnf_conf
echo "proxy=http://${local.proxy.server}:${local.proxy.port}" | sudo tee -a $yum_dnf_conf > /dev/null
echo "proxy_username=${local.proxy.user}" | sudo tee -a $yum_dnf_conf > /dev/null
echo "proxy_password=${local.proxy.password}" | sudo tee -a $yum_dnf_conf > /dev/null

EOF
  ]
    }

}

resource "null_resource" "bastion_register" {
    depends_on  = [null_resource.bastion_init, null_resource.setup_proxy_info]
    count       = var.rhel_subscription_username != "" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = data.ibm_pi_instance_ip.bastion_ip.ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = data.ibm_pi_instance_ip.bastion_public_ip.external_ip
    }

    provisioner "remote-exec" {
        inline = [<<EOF
# FIX for existing stale repos
echo "Moving all file from /etc/yum.repos.d/ to /etc/yum.repos.d.bak/"
mkdir /etc/yum.repos.d.bak/
mv /etc/yum.repos.d/* /etc/yum.repos.d.bak/

# Give some more time to subscription-manager
sudo subscription-manager config --server.server_timeout=600
sudo subscription-manager clean
sudo subscription-manager register --username=${var.rhel_subscription_username} --password=${var.rhel_subscription_password} --force
sudo subscription-manager refresh
sudo subscription-manager attach --auto
EOF
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "sudo rm -rf /tmp/terraform_*"
        ]
    }
}

resource "null_resource" "bastion_packages" {
    depends_on = [null_resource.bastion_init, null_resource.setup_proxy_info, null_resource.bastion_register]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = data.ibm_pi_instance_ip.bastion_ip.ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = data.ibm_pi_instance_ip.bastion_public_ip.external_ip
    }

    provisioner "remote-exec" {
        inline = [
            "#sudo yum update -y --skip-broken",
            "sudo yum install -y wget jq git net-tools vim python3 tar"
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "pip3 install ansible -q"
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "sudo systemctl unmask NetworkManager",
            "sudo systemctl start NetworkManager",
            "for i in $(nmcli device | grep unmanaged | awk '{print $1}'); do echo NM_CONTROLLED=yes | sudo tee -a /etc/sysconfig/network-scripts/ifcfg-$i; done",
            "sudo systemctl restart NetworkManager",
            "sudo systemctl enable NetworkManager"
        ]
    }
}

locals {
    disk_config = {
        volume_size = var.volume_size
        disk_name   = "disk/pv-storage-disk"
    }
    storage_path = "/export"
}

resource "null_resource" "setup_nfs_disk" {
    depends_on  = [null_resource.bastion_packages]
    count       = var.storage_type == "nfs" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = data.ibm_pi_instance_ip.bastion_ip.ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = data.ibm_pi_instance_ip.bastion_public_ip.external_ip
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/create_disk_link.sh", local.disk_config)
        destination = "/tmp/create_disk_link.sh"
    }
    provisioner "remote-exec" {
        inline = [
            "rm -rf mkdir ${local.storage_path}; mkdir -p ${local.storage_path}; chmod -R 755 ${local.storage_path}",
            "sudo chmod +x /tmp/create_disk_link.sh",
            # Fix for copying file from Windows OS having CR
            "sed -i 's/\r//g' /tmp/create_disk_link.sh",
            "/tmp/create_disk_link.sh",
            "sudo mkfs.ext4 -F /dev/${local.disk_config.disk_name}",
            "echo '/dev/${local.disk_config.disk_name} ${local.storage_path} ext4 defaults 0 0' | sudo tee -a /etc/fstab > /dev/null",
            "sudo mount ${local.storage_path}",
        ]
    }
}
