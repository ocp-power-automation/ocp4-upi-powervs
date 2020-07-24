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

resource "null_resource" "bastion_init" {
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = var.bastion_public_ip
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
        ]
    }
}

resource "null_resource" "setup_proxy_info" {
    depends_on  = [null_resource.bastion_init]
    count       = !var.setup_squid_proxy && local.proxy.server != "" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = var.bastion_public_ip
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
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = var.bastion_public_ip
    }

    provisioner "remote-exec" {
        inline = [<<EOF
# FIX for existing stale repos
echo "Moving all file from /etc/yum.repos.d/ to /etc/yum.repos.d.bak/"
mkdir /etc/yum.repos.d.bak/
mv /etc/yum.repos.d/* /etc/yum.repos.d.bak/

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
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = var.bastion_public_ip
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
    count       = (var.storage_type == "nfs" && !var.custom_bastion) || (var.custom_bastion && var.custom_bastion_volume != "") ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = var.bastion_public_ip
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
