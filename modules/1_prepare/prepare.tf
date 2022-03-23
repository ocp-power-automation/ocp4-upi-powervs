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
  bastion_count = lookup(var.bastion, "count", 1)
  proxy = {
    server    = lookup(var.proxy, "server", ""),
    port      = lookup(var.proxy, "port", "3128"),
    user      = lookup(var.proxy, "user", ""),
    password  = lookup(var.proxy, "password", "")
    user_pass = lookup(var.proxy, "user", "") == "" ? "" : "${lookup(var.proxy, "user", "")}:${lookup(var.proxy, "password", "")}@"
    no_proxy  = "127.0.0.1,localhost,.${var.cluster_id}.${var.cluster_domain}"
  }
}

data "ibm_pi_catalog_images" "catalog_images" {
  pi_cloud_instance_id = var.service_instance_id
}

locals {
  catalog_bastion_image = [for x in data.ibm_pi_catalog_images.catalog_images.images : x if x.name == var.rhel_image_name]
  bastion_image_id      = length(local.catalog_bastion_image) == 0 ? data.ibm_pi_image.bastion[0].id : local.catalog_bastion_image[0].image_id
  bastion_storage_pool  = length(local.catalog_bastion_image) == 0 ? data.ibm_pi_image.bastion[0].storage_pool : local.catalog_bastion_image[0].storage_pool
}

data "ibm_pi_image" "bastion" {
  count                = length(local.catalog_bastion_image) == 0 ? 1 : 0
  pi_image_name        = var.rhel_image_name
  pi_cloud_instance_id = var.service_instance_id
}

data "ibm_pi_network" "network" {
  pi_network_name      = var.network_name
  pi_cloud_instance_id = var.service_instance_id
}

resource "ibm_pi_network" "public_network" {
  pi_network_name      = "${var.name_prefix}pub-net"
  pi_cloud_instance_id = var.service_instance_id
  pi_network_type      = "pub-vlan"
  pi_dns               = var.network_dns
}

resource "ibm_pi_key" "key" {
  pi_cloud_instance_id = var.service_instance_id
  pi_key_name          = "${var.name_prefix}keypair"
  pi_ssh_key           = var.public_key
}

resource "ibm_pi_volume" "volume" {
  count = var.storage_type == "nfs" ? 1 : 0

  pi_volume_size       = var.volume_size
  pi_volume_name       = "${var.name_prefix}${var.storage_type}-volume"
  pi_volume_pool       = local.bastion_storage_pool
  pi_volume_shareable  = var.volume_shareable
  pi_cloud_instance_id = var.service_instance_id
}

resource "ibm_pi_instance" "bastion" {
  count = local.bastion_count

  pi_memory            = var.bastion["memory"]
  pi_processors        = var.bastion["processors"]
  pi_instance_name     = "${var.name_prefix}bastion-${count.index}"
  pi_proc_type         = var.processor_type
  pi_image_id          = local.bastion_image_id
  pi_key_pair_name     = ibm_pi_key.key.key_id
  pi_sys_type          = var.system_type
  pi_cloud_instance_id = var.service_instance_id
  pi_health_status     = var.bastion_health_status
  pi_volume_ids        = var.storage_type == "nfs" ? ibm_pi_volume.volume.*.volume_id : null
  pi_storage_pool      = local.bastion_storage_pool

  pi_network {
    network_id = ibm_pi_network.public_network.network_id
  }
  pi_network {
    network_id = data.ibm_pi_network.network.id
  }
}

data "ibm_pi_instance_ip" "bastion_ip" {
  count      = local.bastion_count
  depends_on = [ibm_pi_instance.bastion]

  pi_instance_name     = ibm_pi_instance.bastion[count.index].pi_instance_name
  pi_network_name      = data.ibm_pi_network.network.name
  pi_cloud_instance_id = var.service_instance_id
}

data "ibm_pi_instance_ip" "bastion_public_ip" {
  count      = local.bastion_count
  depends_on = [ibm_pi_instance.bastion]

  pi_instance_name     = ibm_pi_instance.bastion[count.index].pi_instance_name
  pi_network_name      = ibm_pi_network.public_network.pi_network_name
  pi_cloud_instance_id = var.service_instance_id
}

resource "null_resource" "bastion_init" {
  count = local.bastion_count

  connection {
    type        = "ssh"
    user        = var.rhel_username
    host        = data.ibm_pi_instance_ip.bastion_public_ip[count.index].external_ip
    private_key = var.private_key
    agent       = var.ssh_agent
    timeout     = "${var.connection_timeout}m"
  }
  provisioner "remote-exec" {
    inline = [
      "whoami"
    ]
  }
  provisioner "file" {
    content     = var.private_key
    destination = ".ssh/id_rsa"
  }
  provisioner "file" {
    content     = var.public_key
    destination = ".ssh/id_rsa.pub"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo chmod 600 .ssh/id_rsa*",
      "sudo sed -i.bak -e 's/^ - set_hostname/# - set_hostname/' -e 's/^ - update_hostname/# - update_hostname/' /etc/cloud/cloud.cfg",
      "sudo hostnamectl set-hostname --static ${lower(var.name_prefix)}bastion-${count.index}.${var.cluster_domain}",
      "echo 'HOSTNAME=${lower(var.name_prefix)}bastion-${count.index}.${var.cluster_domain}' | sudo tee -a /etc/sysconfig/network > /dev/null",
      "sudo hostname -F /etc/hostname",
      "echo 'vm.max_map_count = 262144' | sudo tee --append /etc/sysctl.conf > /dev/null",
      # Set SMT to user specified value; Should not fail for invalid values.
      "sudo ppc64_cpu --smt=${var.rhel_smt} | true",
      # Set mtu to 1450 for public interface.
      "sudo ip link set dev $(ip r | grep \"${ibm_pi_network.public_network.pi_cidr} dev\" | awk '{print $3}') mtu 1450",
      "echo MTU=1450 | sudo tee -a /etc/sysconfig/network-scripts/ifcfg-$(ip r | grep ${ibm_pi_network.public_network.pi_cidr} | awk '{print $3}')",
      # Set specified mtu for private interface.
      "sudo ip link set dev $(ip r | grep \"${data.ibm_pi_network.network.cidr} dev\" | awk '{print $3}') mtu ${var.private_network_mtu}",
      "echo MTU=${var.private_network_mtu} | sudo tee -a /etc/sysconfig/network-scripts/ifcfg-$(ip r | grep ${data.ibm_pi_network.network.cidr} | awk '{print $3}')"
    ]
  }
}

resource "null_resource" "setup_proxy_info" {
  count      = ! var.setup_squid_proxy && local.proxy.server != "" ? local.bastion_count : 0
  depends_on = [null_resource.bastion_init]

  connection {
    type        = "ssh"
    user        = var.rhel_username
    host        = data.ibm_pi_instance_ip.bastion_public_ip[count.index].external_ip
    private_key = var.private_key
    agent       = var.ssh_agent
    timeout     = "${var.connection_timeout}m"
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
  count      = (var.rhel_subscription_username == "" || var.rhel_subscription_username == "<subscription-id>") && var.rhel_subscription_org == "" ? 0 : local.bastion_count
  depends_on = [null_resource.bastion_init, null_resource.setup_proxy_info]
  triggers = {
    external_ip        = data.ibm_pi_instance_ip.bastion_public_ip[count.index].external_ip
    rhel_username      = var.rhel_username
    private_key        = var.private_key
    ssh_agent          = var.ssh_agent
    connection_timeout = var.connection_timeout
  }

  connection {
    type        = "ssh"
    user        = self.triggers.rhel_username
    host        = self.triggers.external_ip
    private_key = self.triggers.private_key
    agent       = self.triggers.ssh_agent
    timeout     = "${self.triggers.connection_timeout}m"
  }

  provisioner "remote-exec" {
    inline = [<<EOF

# Give some more time to subscription-manager
sudo subscription-manager config --server.server_timeout=600
sudo subscription-manager clean
if [[ '${var.rhel_subscription_username}' != '' && '${var.rhel_subscription_username}' != '<subscription-id>' ]]; then 
    sudo subscription-manager register --username='${var.rhel_subscription_username}' --password='${var.rhel_subscription_password}' --force
else
    sudo subscription-manager register --org='${var.rhel_subscription_org}' --activationkey='${var.rhel_subscription_activationkey}' --force
fi
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

  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      user        = self.triggers.rhel_username
      host        = self.triggers.external_ip
      private_key = self.triggers.private_key
      agent       = self.triggers.ssh_agent
      timeout     = "2m"
    }
    when       = destroy
    on_failure = continue
    inline = [
      "sudo subscription-manager unregister",
      "sudo subscription-manager remove --all",
    ]
  }
}

resource "null_resource" "enable_repos" {
  count      = local.bastion_count
  depends_on = [null_resource.bastion_init, null_resource.setup_proxy_info, null_resource.bastion_register]

  connection {
    type        = "ssh"
    user        = var.rhel_username
    host        = data.ibm_pi_instance_ip.bastion_public_ip[count.index].external_ip
    private_key = var.private_key
    agent       = var.ssh_agent
    timeout     = "${var.connection_timeout}m"
  }

  provisioner "remote-exec" {
    inline = [<<EOF
# Additional repo for installing ansible package
if ( [[ -z "${var.rhel_subscription_username}" ]] || [[ "${var.rhel_subscription_username}" == "<subscription-id>" ]] ) && [[ -z "${var.rhel_subscription_org}" ]]; then
  sudo yum install -y epel-release
else
  sudo subscription-manager repos --enable ${var.ansible_repo_name}
fi
EOF
    ]
  }
}

resource "null_resource" "bastion_packages" {
  count      = local.bastion_count
  depends_on = [null_resource.bastion_init, null_resource.setup_proxy_info, null_resource.bastion_register, null_resource.enable_repos]

  connection {
    type        = "ssh"
    user        = var.rhel_username
    host        = data.ibm_pi_instance_ip.bastion_public_ip[count.index].external_ip
    private_key = var.private_key
    agent       = var.ssh_agent
    timeout     = "${var.connection_timeout}m"
  }

  provisioner "remote-exec" {
    inline = [
      "#sudo yum update -y --skip-broken",
      "sudo yum install -y wget jq git net-tools vim python3 tar"
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
  provisioner "remote-exec" {
    inline = [
      "sudo yum install -y ansible-2.9.*"
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
  count      = var.storage_type == "nfs" ? 1 : 0
  depends_on = [null_resource.bastion_packages]

  connection {
    type        = "ssh"
    user        = var.rhel_username
    host        = data.ibm_pi_instance_ip.bastion_public_ip[count.index].external_ip
    private_key = var.private_key
    agent       = var.ssh_agent
    timeout     = "${var.connection_timeout}m"
  }
  provisioner "file" {
    content     = templatefile("${path.module}/templates/create_disk_link.sh", local.disk_config)
    destination = "/tmp/create_disk_link.sh"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo rm -rf mkdir ${local.storage_path}; sudo mkdir -p ${local.storage_path}; sudo chmod -R 755 ${local.storage_path}",
      "sudo chmod +x /tmp/create_disk_link.sh",
      # Fix for copying file from Windows OS having CR
      "sudo sed -i 's/\r//g' /tmp/create_disk_link.sh",
      "sudo /tmp/create_disk_link.sh",
      "sudo mkfs.ext4 -F /dev/${local.disk_config.disk_name}",
      "echo '/dev/${local.disk_config.disk_name} ${local.storage_path} ext4 defaults 0 0' | sudo tee -a /etc/fstab > /dev/null",
      "sudo mount ${local.storage_path}",
    ]
  }
}

# Workaround for unable to access RHEL 8.3 instance after reboot. TODO: Remove when permanently fixed.
resource "null_resource" "rhel83_fix" {
  count      = local.bastion_count
  depends_on = [null_resource.bastion_packages, null_resource.setup_nfs_disk]

  connection {
    type        = "ssh"
    user        = var.rhel_username
    host        = data.ibm_pi_instance_ip.bastion_public_ip[count.index].external_ip
    private_key = var.private_key
    agent       = var.ssh_agent
    timeout     = "${var.connection_timeout}m"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo yum remove cloud-init --noautoremove -y",
    ]
  }
}

resource "ibm_pi_network_port" "bastion_vip" {
  count      = local.bastion_count > 1 ? 1 : 0
  depends_on = [ibm_pi_instance.bastion]

  pi_network_name      = data.ibm_pi_network.network.name
  pi_cloud_instance_id = var.service_instance_id
}

resource "ibm_pi_network_port" "bastion_internal_vip" {
  count      = local.bastion_count > 1 ? 1 : 0
  depends_on = [ibm_pi_instance.bastion]

  pi_network_name      = ibm_pi_network.public_network.pi_network_name
  pi_cloud_instance_id = var.service_instance_id
}
