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
  wildcard_dns   = ["nip.io", "xip.io", "sslip.io"]
  cluster_domain = contains(local.wildcard_dns, var.cluster_domain) ? "${var.bastion_external_vip != "" ? var.bastion_external_vip : var.bastion_public_ip[0]}.${var.cluster_domain}" : var.cluster_domain
  worker = {
    volume_count = lookup(var.worker, "data_volume_count", 0),
    volume_size  = lookup(var.worker, "data_volume_size", 100)
  }
  master = {
    volume_count = lookup(var.master, "data_volume_count", 0),
    volume_size  = lookup(var.master, "data_volume_size", 100)
  }
}

data "ibm_pi_network" "network" {
  pi_network_name      = var.network_name
  pi_cloud_instance_id = var.service_instance_id
}

# RHCOS Image Import
resource "ibm_pi_image" "rhcos_image_import" {
  count = var.rhcos_import_image ? 1 : 0

  pi_image_name             = "${var.name_prefix}rhcos-${var.rhcos_import_image_storage_type}-image"
  pi_cloud_instance_id      = var.service_instance_id
  pi_image_bucket_name      = "rhcos-powervs-images-${var.rhcos_import_bucket_region}"
  pi_image_bucket_region    = var.rhcos_import_bucket_region
  pi_image_bucket_file_name = var.rhcos_import_image_filename
  pi_image_storage_type     = var.rhcos_import_image_storage_type
}

data "ibm_pi_image" "rhcos" {
  depends_on = [ibm_pi_image.rhcos_image_import]

  pi_image_name        = var.rhcos_import_image ? ibm_pi_image.rhcos_image_import[0].pi_image_name : var.rhcos_image_name
  pi_cloud_instance_id = var.service_instance_id
}


#bootstrap
data "ignition_config" "bootstrap" {
  merge {
    source = "http://${var.bastion_ip}:8080/ignition/bootstrap.ign"
  }
  files = [data.ignition_file.b_hostname.rendered]
}

data "ignition_file" "b_hostname" {
  overwrite = true
  mode      = "420" // 0644
  path      = "/etc/hostname"
  content {
    content = <<EOF
${var.node_prefix}bootstrap.${var.cluster_id}.${local.cluster_domain}
EOF
  }
}

resource "ibm_pi_instance" "bootstrap" {
  # Only 1 node is supported
  count = var.bootstrap["count"] == 0 ? 0 : 1

  pi_memory            = var.bootstrap["memory"]
  pi_processors        = var.bootstrap["processors"]
  pi_instance_name     = "${var.name_prefix}bootstrap"
  pi_proc_type         = var.processor_type
  pi_image_id          = data.ibm_pi_image.rhcos.id
  pi_sys_type          = var.system_type
  pi_cloud_instance_id = var.service_instance_id

  pi_user_data = base64encode(data.ignition_config.bootstrap.rendered)

  # Not needed by RHCOS but required by resource
  pi_key_pair_name = "${var.name_prefix}keypair"
  pi_health_status = "WARNING"
  pi_storage_pool  = data.ibm_pi_image.rhcos.storage_pool

  pi_network {
    network_id = data.ibm_pi_network.network.id
  }
}
resource "ibm_pi_instance_action" "bootstrap_stop" {
  count = var.bootstrap["count"] == 0 ? 0 : 1

  pi_cloud_instance_id = var.service_instance_id
  pi_instance_id       = ibm_pi_instance.bootstrap[count.index].instance_id
  pi_action            = "immediate-shutdown"
  pi_health_status     = "WARNING"
}

#master
data "ignition_config" "master" {
  count = var.master["count"]
  merge {
    source = "http://${var.bastion_ip}:8080/ignition/master.ign"
  }
  files = [data.ignition_file.m_hostname[count.index].rendered]
}

data "ignition_file" "m_hostname" {
  count     = var.master["count"]
  overwrite = true
  mode      = "420" // 0644
  path      = "/etc/hostname"
  content {
    content = <<EOF
${var.node_prefix}master-${count.index}.${var.cluster_id}.${local.cluster_domain}
EOF
  }
}

resource "ibm_pi_instance" "master" {
  count      = var.master["count"]
  depends_on = [ibm_pi_volume.master]

  pi_memory            = var.master["memory"]
  pi_processors        = var.master["processors"]
  pi_instance_name     = "${var.name_prefix}master-${count.index}"
  pi_proc_type         = var.processor_type
  pi_image_id          = data.ibm_pi_image.rhcos.id
  pi_sys_type          = var.system_type
  pi_cloud_instance_id = var.service_instance_id
  pi_volume_ids        = local.master.volume_count == 0 ? null : [for ix in range(local.master.volume_count) : ibm_pi_volume.master.*.volume_id[(count.index * local.master.volume_count) + ix]]

  pi_user_data = base64encode(data.ignition_config.master[count.index].rendered)

  # Not needed by RHCOS but required by resource
  pi_key_pair_name = "${var.name_prefix}keypair"
  pi_health_status = "WARNING"
  pi_storage_pool  = data.ibm_pi_image.rhcos.storage_pool

  pi_network {
    network_id = data.ibm_pi_network.network.id
  }
}
resource "ibm_pi_instance_action" "master_stop" {
  count = var.master["count"]

  pi_cloud_instance_id = var.service_instance_id
  pi_instance_id       = ibm_pi_instance.master[count.index].instance_id
  pi_action            = "immediate-shutdown"
  pi_health_status     = "WARNING"
}

resource "ibm_pi_volume" "master" {
  count = local.master.volume_count * var.master["count"]

  pi_volume_size       = local.master.volume_size
  pi_volume_name       = "${var.name_prefix}master-${count.index}-volume"
  pi_volume_pool       = data.ibm_pi_image.rhcos.storage_pool
  pi_volume_shareable  = var.volume_shareable
  pi_cloud_instance_id = var.service_instance_id
}


#worker
data "ignition_file" "w_hostname" {
  count     = var.worker["count"]
  overwrite = true
  mode      = "420" // 0644
  path      = "/etc/hostname"

  content {
    content = <<EOF
${var.node_prefix}worker-${count.index}.${var.cluster_id}.${local.cluster_domain}
EOF
  }
}

data "ignition_config" "worker" {
  count = var.worker["count"]
  merge {
    source = "http://${var.bastion_ip}:8080/ignition/worker.ign"
  }
  files = [data.ignition_file.w_hostname[count.index].rendered]
}

resource "ibm_pi_instance" "worker" {
  count      = var.worker["count"]
  depends_on = [ibm_pi_volume.worker]

  pi_memory            = var.worker["memory"]
  pi_processors        = var.worker["processors"]
  pi_instance_name     = "${var.name_prefix}worker-${count.index}"
  pi_proc_type         = var.processor_type
  pi_image_id          = data.ibm_pi_image.rhcos.id
  pi_sys_type          = var.system_type
  pi_cloud_instance_id = var.service_instance_id
  pi_volume_ids        = local.worker.volume_count == 0 ? null : [for ix in range(local.worker.volume_count) : ibm_pi_volume.worker.*.volume_id[(count.index * local.worker.volume_count) + ix]]

  pi_user_data = base64encode(data.ignition_config.worker[count.index].rendered)

  # Not needed by RHCOS but required by resource
  pi_key_pair_name = "${var.name_prefix}keypair"
  pi_health_status = "WARNING"
  pi_storage_pool  = data.ibm_pi_image.rhcos.storage_pool

  pi_network {
    network_id = data.ibm_pi_network.network.id
  }
}
resource "ibm_pi_instance_action" "worker_stop" {
  count = var.worker["count"]

  pi_cloud_instance_id = var.service_instance_id
  pi_instance_id       = ibm_pi_instance.worker[count.index].instance_id
  pi_action            = "immediate-shutdown"
  pi_health_status     = "WARNING"
}

resource "null_resource" "remove_worker" {
  count      = var.worker["count"]
  depends_on = [ibm_pi_instance.worker]
  triggers = {
    external_ip    = var.bastion_public_ip[0]
    rhel_username  = var.rhel_username
    private_key    = var.private_key
    ssh_agent      = var.ssh_agent
    node_prefix    = var.node_prefix
    cluster_id     = var.cluster_id
    cluster_domain = local.cluster_domain
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
    inline = [<<EOF
oc adm cordon ${self.triggers.node_prefix}worker-${count.index}.${self.triggers.cluster_id}.${self.triggers.cluster_domain}
oc adm drain ${self.triggers.node_prefix}worker-${count.index}.${self.triggers.cluster_id}.${self.triggers.cluster_domain} --force --delete-emptydir-data --ignore-daemonsets --timeout=100s
oc delete node ${self.triggers.node_prefix}worker-${count.index}.${self.triggers.cluster_id}.${self.triggers.cluster_domain}
EOF
    ]
  }
}

resource "ibm_pi_volume" "worker" {
  count = local.worker.volume_count * var.worker["count"]

  pi_volume_size       = local.worker.volume_size
  pi_volume_name       = "${var.name_prefix}worker-${count.index}-volume"
  pi_volume_pool       = data.ibm_pi_image.rhcos.storage_pool
  pi_volume_shareable  = var.volume_shareable
  pi_cloud_instance_id = var.service_instance_id
}


data "ibm_pi_instance_ip" "bootstrap_ip" {
  depends_on = [ibm_pi_instance.bootstrap]
  count      = var.bootstrap["count"] == 0 ? 0 : 1

  pi_instance_name     = ibm_pi_instance.bootstrap[count.index].pi_instance_name
  pi_network_name      = var.network_name
  pi_cloud_instance_id = var.service_instance_id
}

data "ibm_pi_instance_ip" "master_ip" {
  depends_on = [ibm_pi_instance.master]
  count      = var.master["count"]

  pi_instance_name     = ibm_pi_instance.master[count.index].pi_instance_name
  pi_network_name      = var.network_name
  pi_cloud_instance_id = var.service_instance_id
}

data "ibm_pi_instance_ip" "worker_ip" {
  depends_on = [ibm_pi_instance.worker]
  count      = var.worker["count"]

  pi_instance_name     = ibm_pi_instance.worker[count.index].pi_instance_name
  pi_network_name      = var.network_name
  pi_cloud_instance_id = var.service_instance_id
}
