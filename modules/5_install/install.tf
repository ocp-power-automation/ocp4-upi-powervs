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

    public_vrrp = {
        virtual_router_id   = var.bastion_internal_vip == "" ? "" : split(".", var.bastion_internal_vip)[3]
        virtual_ipaddress   = var.bastion_internal_vip
        password            = uuid()
    }

    wildcard_dns    = ["nip.io", "xip.io", "sslip.io"]
    cluster_domain  = contains(local.wildcard_dns, var.cluster_domain) ? "${var.bastion_external_vip != "" ? var.bastion_external_vip : var.bastion_public_ip[0]}.${var.cluster_domain}" : var.cluster_domain

    local_registry  = {
        enable_local_registry   = var.enable_local_registry
        registry_image          = var.local_registry_image
        ocp_release_repo        = "ocp4/openshift4"
        ocp_release_tag         = var.ocp_release_tag
        ocp_release_name        = var.ocp_release_name
    }

    helpernode_vars = {
        cluster_domain  = local.cluster_domain
        cluster_id      = var.cluster_id
        bastion_ip      = var.bastion_vip != "" ? var.bastion_vip : var.bastion_ip[0]
        bastion_name    = var.bastion_vip != "" ? "${var.cluster_id}-bastion" : "${var.cluster_id}-bastion-0"
        isHA            = var.bastion_vip != ""
        bastion_master_ip   = var.bastion_ip[0]
        bastion_backup_ip   = length(var.bastion_ip) > 1 ? slice(var.bastion_ip, 1, length(var.bastion_ip)) : []
        forwarders      = var.dns_forwarders
        gateway_ip      = var.gateway_ip
        netmask         = cidrnetmask(var.cidr)
        broadcast       = cidrhost(var.cidr,-1)
        ipid            = cidrhost(var.cidr, 0)
        pool            = {"start": cidrhost(var.cidr,2),
                            "end": cidrhost(var.cidr,-2)}
        chrony_config           = var.chrony_config
        chrony_config_servers   = var.chrony_config_servers

        bootstrap_info  = {
            ip = var.bootstrap_ip
            mac = var.bootstrap_mac
            name = "bootstrap"
        }
        master_info     = [ for ix in range(length(var.master_ips)) :
            {
                ip = var.master_ips[ix],
                mac = var.master_macs[ix],
                name = "master-${ix}"
            }
        ]
        worker_info     = [ for ix in range(length(var.worker_ips)) :
            {
                ip = var.worker_ips[ix],
                mac = var.worker_macs[ix],
                name = "worker-${ix}"
            }
        ]

        local_registry           = local.local_registry
        client_tarball           = var.openshift_client_tarball
        install_tarball          = var.openshift_install_tarball
    }

    helpernode_inventory = {
        bastion_ip      = var.bastion_ip
    }

    install_inventory = {
        bastion_hosts   = [for ix in range(length(var.bastion_ip)) : "${var.cluster_id}-bastion-${ix}"]
        bootstrap_host  = var.bootstrap_ip == "" ? "" : "bootstrap"
        master_hosts    = [for ix in range(length(var.master_ips)) : "master-${ix}"]
        worker_hosts    = [for ix in range(length(var.worker_ips)) : "worker-${ix}"]
    }

    proxy = {
        server      = lookup(var.proxy, "server", ""),
        port        = lookup(var.proxy, "port", "3128"),
        user_pass   = lookup(var.proxy, "user", "") == "" ? "" : "${lookup(var.proxy, "user", "")}:${lookup(var.proxy, "password", "")}@"
    }

    local_registry_ocp_image = "registry.${var.cluster_id}.${local.cluster_domain}:5000/${local.local_registry.ocp_release_repo}:${var.ocp_release_tag}"

    install_vars = {
        bastion_vip             = var.bastion_vip
        cluster_id              = var.cluster_id
        cluster_domain          = local.cluster_domain
        pull_secret             = var.pull_secret
        public_ssh_key          = var.public_key
        storage_type            = var.storage_type
        log_level               = var.log_level
        release_image_override  = var.enable_local_registry ? local.local_registry_ocp_image : var.release_image_override
        enable_local_registry   = var.enable_local_registry
        rhcos_kernel_options    = var.rhcos_kernel_options
        chrony_config           = var.chrony_config
        chrony_config_servers   = var.chrony_config_servers
        chrony_allow_range      = var.cidr
        setup_squid_proxy       = var.setup_squid_proxy
        squid_source_range      = var.cidr
        proxy_url               = local.proxy.server == "" ? "" : "http://${local.proxy.user_pass}${local.proxy.server}:${local.proxy.port}"
        no_proxy                = var.cidr
        cni_network_provider    = var.cni_network_provider
    }

    powervs_config_vars = {
        ibm_cloud_dl_endpoint_net_cidr = var.ibm_cloud_dl_endpoint_net_cidr
        ibm_cloud_http_proxy           = var.ibm_cloud_http_proxy
        ocp_node_net_gw                = var.gateway_ip
    }

    upgrade_vars = {
        upgrade_version = var.upgrade_version
        pause_time      = var.upgrade_pause_time
        delay_time      = var.upgrade_delay_time
    }
}

resource "null_resource" "config" {

    triggers = {
       worker_count = length(var.worker_ips)
    }

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_public_ip[0]
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "remote-exec" {
        inline = [
            "mkdir -p .openshift",
            "rm -rf ocp4-helpernode",
            "echo 'Cloning into ocp4-helpernode...'",
            "git clone ${var.helpernode_repo} --quiet",
            "cd ocp4-helpernode && git checkout ${var.helpernode_tag}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/helpernode_inventory", local.helpernode_inventory)
        destination = "~/ocp4-helpernode/inventory"
    }
    provisioner "file" {
        content     = var.pull_secret
        destination = "~/.openshift/pull-secret"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/helpernode_vars.yaml", local.helpernode_vars)
        destination = "~/ocp4-helpernode/helpernode_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "sed -i \"/^helper:.*/a \\ \\ networkifacename: $(ip r | grep \"${var.cidr} dev\" | awk '{print $3}')\" ocp4-helpernode/helpernode_vars.yaml",
            "echo 'Running ocp4-helpernode playbook...'",
            "cd ocp4-helpernode && ansible-playbook -e @helpernode_vars.yaml tasks/main.yml ${var.ansible_extra_options}"
        ]
    }
}

resource "null_resource" "configure_public_vip" {
    count       = var.bastion_count > 1 ? var.bastion_count : 0
    depends_on  = [null_resource.config]

    triggers = {
       worker_count = length(var.worker_ips)
    }

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_public_ip[count.index]
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "file" {
        content     = templatefile("${path.module}/templates/keepalived_vrrp_instance.tpl", local.public_vrrp)
        destination = "/tmp/keepalived_vrrp_instance"
    }
    provisioner "remote-exec" {
        inline = [
            # Set state=MASTER,priority=100 for first bastion and state=BACKUP,priority=90 for others.
            "sed -i \"s/state <STATE>/state ${count.index == 0 ? "MASTER" : "BACKUP"}/\" /tmp/keepalived_vrrp_instance",
            "sed -i \"s/priority <PRIORITY>/priority ${count.index == 0 ? "100" : "90"}/\" /tmp/keepalived_vrrp_instance",
            "sed -i \"s/interface <INTERFACE>/interface $(ip r | grep ${var.public_cidr} | awk '{print $3}')/\" /tmp/keepalived_vrrp_instance",
            "cat /tmp/keepalived_vrrp_instance >> /etc/keepalived/keepalived.conf",
            "sudo systemctl restart keepalived"
        ]
    }
}

resource "null_resource" "install" {
    depends_on = [null_resource.config, null_resource.configure_public_vip]

    triggers = {
       worker_count = length(var.worker_ips)
    }

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_public_ip[0]
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "remote-exec" {
        inline = [
            "rm -rf ocp4-playbooks",
            "echo 'Cloning into ocp4-playbooks...'",
            "git clone ${var.install_playbook_repo} --quiet",
            "cd ocp4-playbooks && git checkout ${var.install_playbook_tag}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/install_inventory", local.install_inventory)
        destination = "~/ocp4-playbooks/inventory"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/install_vars.yaml", local.install_vars)
        destination = "~/ocp4-playbooks/install_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp install playbook...'",
            "cd ocp4-playbooks && ansible-playbook -i inventory -e @install_vars.yaml playbooks/install.yaml ${var.ansible_extra_options}"
        ]
    }
}

resource "null_resource" "powervs_config" {
    depends_on = [null_resource.install]
    count      = var.ibm_cloud_dl_endpoint_net_cidr != "" && var.ibm_cloud_http_proxy != "" ? 1 : 0

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_public_ip[0]
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "file" {
        content     = templatefile("${path.module}/templates/powervs_config_vars.yaml", local.powervs_config_vars)
        destination = "~/ocp4-playbooks/powervs_config_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "sed -i \"$ a ocp_node_net_intf: \\\"$(ip r | grep \"${var.cidr} dev\" | awk '{print $3}')\\\"\" ocp4-playbooks/powervs_config_vars.yaml",
            "echo 'Running powervs specific nodes configuration playbook...'",
            "cd ocp4-playbooks && ansible-playbook -i inventory -e @powervs_config_vars.yaml playbooks/powervs_config.yaml ${var.ansible_extra_options}"
        ]
    }
}

resource "null_resource" "upgrade" {
    depends_on = [null_resource.install, null_resource.powervs_config]
    count      = var.upgrade_version != "" ? 1 : 0
    triggers = {
       upgrade_version = var.upgrade_version
    }

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_public_ip[0]
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "file" {
        content     = templatefile("${path.module}/templates/upgrade_vars.yaml", local.upgrade_vars)
        destination = "~/ocp4-playbooks/upgrade_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp upgrade playbook...'",
            "cd ocp4-playbooks && ansible-playbook -i inventory -e @upgrade_vars.yaml playbooks/upgrade.yaml ${var.ansible_extra_options}"
        ]
    }
}

