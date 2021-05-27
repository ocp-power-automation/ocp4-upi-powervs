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

data "ibm_pi_network" "network" {
  pi_network_name      = var.network_name
  pi_cloud_instance_id = var.service_instance_id
}

data "ibm_pi_image" "rhcos" {
  pi_image_name        = var.rhcos_image_name
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
bootstrap
EOF
  }
}

resource "ibm_pi_instance" "bootstrap" {
  # Only 1 node is supported
  count = var.bootstrap["count"] == 0 ? 0 : 1

  pi_memory            = var.bootstrap["memory"]
  pi_processors        = var.bootstrap["processors"]
  pi_instance_name     = "${var.name_prefix}-bootstrap"
  pi_proc_type         = var.processor_type
  pi_image_id          = data.ibm_pi_image.rhcos.id
  pi_sys_type          = var.system_type
  pi_cloud_instance_id = var.service_instance_id
  pi_network_ids       = [data.ibm_pi_network.network.id]

  # Inject ignition source timeout to force ignition fail when HTTP file is not available for 500s. This will reboot the node and try ignition fetch process again.
  pi_user_data = base64encode(replace(data.ignition_config.bootstrap.rendered, "\"timeouts\":{}", "\"timeouts\":{\"httpTotal\":500}"))

  # Not needed by RHCOS but required by resource
  pi_key_pair_name = "${var.name_prefix}-keypair"
  pi_health_status = "WARNING"
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
master-${count.index}
EOF
  }
}

resource "ibm_pi_instance" "master" {
  count = var.master["count"]

  pi_memory            = var.master["memory"]
  pi_processors        = var.master["processors"]
  pi_instance_name     = "${var.name_prefix}-master-${count.index}"
  pi_proc_type         = var.processor_type
  pi_image_id          = data.ibm_pi_image.rhcos.id
  pi_sys_type          = var.system_type
  pi_cloud_instance_id = var.service_instance_id
  pi_network_ids       = [data.ibm_pi_network.network.id]
  pi_volume_ids        = var.master_volume_size == "" ? null : ibm_pi_volume.master[count.index].*.volume_id

  # Inject ignition source timeout to force ignition fail when HTTP file is not available for 500s. This will reboot the node and try ignition fetch process again.
  pi_user_data = base64encode(replace(data.ignition_config.master[count.index].rendered, "\"timeouts\":{}", "\"timeouts\":{\"httpTotal\":500}"))

  # Not needed by RHCOS but required by resource
  pi_key_pair_name = "${var.name_prefix}-keypair"
  pi_health_status = "WARNING"
}

resource "ibm_pi_volume" "master" {
  count = var.master_volume_size == "" ? 0 : var.master["count"]

  pi_volume_size       = var.master_volume_size
  pi_volume_name       = "${var.name_prefix}-master-${count.index}-volume"
  pi_volume_type       = data.ibm_pi_image.rhcos.storage_type
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
worker-${count.index}
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
  count = var.worker["count"]

  pi_memory            = var.worker["memory"]
  pi_processors        = var.worker["processors"]
  pi_instance_name     = "${var.name_prefix}-worker-${count.index}"
  pi_proc_type         = var.processor_type
  pi_image_id          = data.ibm_pi_image.rhcos.id
  pi_sys_type          = var.system_type
  pi_cloud_instance_id = var.service_instance_id
  pi_network_ids       = [data.ibm_pi_network.network.id]
  pi_volume_ids        = var.worker_volume_size == "" ? null : ibm_pi_volume.worker[count.index].*.volume_id

  # Inject ignition source timeout to force ignition fail when HTTP file is not available for 500s. This will reboot the node and try ignition fetch process again.
  pi_user_data = base64encode(replace(data.ignition_config.worker[count.index].rendered, "\"timeouts\":{}", "\"timeouts\":{\"httpTotal\":500}"))

  # Not needed by RHCOS but required by resource
  pi_key_pair_name = "${var.name_prefix}-keypair"
  pi_health_status = "WARNING"
}

resource "null_resource" "remove_worker" {
  count      = var.worker["count"]
  depends_on = [ibm_pi_instance.worker]
  triggers = {
    external_ip   = var.bastion_public_ip[0]
    rhel_username = var.rhel_username
    private_key   = var.private_key
    ssh_agent     = var.ssh_agent
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
oc adm cordon worker-${count.index}
oc adm drain worker-${count.index} --force --delete-local-data --ignore-daemonsets --timeout=180s
oc delete node worker-${count.index}
EOF
    ]
  }
}

resource "ibm_pi_volume" "worker" {
  count = var.worker_volume_size == "" ? 0 : var.worker["count"]

  pi_volume_size       = var.worker_volume_size
  pi_volume_name       = "${var.name_prefix}-worker-${count.index}-volume"
  pi_volume_type       = data.ibm_pi_image.rhcos.storage_type
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
