provider "ibm" {
    ibmcloud_api_key = var.ibmcloud_api_key
    region           = var.ibmcloud_region
    zone             = var.ibmcloud_zone
}

resource "random_id" "label" {
    count = var.cluster_id == "" ? 1 : 0
    byte_length = "2" # Since we use the hex, the word lenght would double
    prefix = "${var.cluster_id_prefix}-"
}

locals {
    # Generates cluster_id as combination of cluster_id_prefix + (random_id or user-defined cluster_id)
    cluster_id  = var.cluster_id == "" ? random_id.label[0].hex : "${var.cluster_id_prefix}-${var.cluster_id}"
}

module "bastion" {
    source                          = "./modules/0_bastion"

    custom_bastion                  = var.custom_bastion
    custom_bastion_name             = var.custom_bastion_name
    custom_bastion_public_network   = var.custom_bastion_public_network
    custom_bastion_volume           = var.custom_bastion_volume
    bastion                         = var.bastion
    service_instance_id             = var.service_instance_id
    cluster_id                      = local.cluster_id
    rhel_image_name                 = var.rhel_image_name
    processor_type                  = var.processor_type
    system_type                     = var.system_type
    network_name                    = var.network_name
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    public_key                      = local.public_key
    ssh_agent                       = var.ssh_agent
    rhel_subscription_username      = var.rhel_subscription_username
    rhel_subscription_password      = var.rhel_subscription_password
    storage_type                    = var.storage_type
    volume_type                     = var.volume_type
    volume_size                     = var.volume_size
    volume_shareable                = var.volume_shareable
}

module "prepare" {
    source                          = "./modules/1_prepare"

    custom_bastion                  = var.custom_bastion
    custom_bastion_volume           = var.custom_bastion_volume
    bastion_ip                      = module.bastion.bastion_ip
    bastion_public_ip               = module.bastion.bastion_public_ip
    cluster_id                      = local.cluster_id
    cluster_domain                  = var.cluster_domain
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    public_key                      = local.public_key
    ssh_agent                       = var.ssh_agent
    rhel_subscription_username      = var.rhel_subscription_username
    rhel_subscription_password      = var.rhel_subscription_password
    storage_type                    = var.storage_type
    volume_size                     = var.volume_size
    setup_squid_proxy               = var.setup_squid_proxy
    proxy                           = var.proxy
}

module "nodes" {
    source                          = "./modules/4_nodes"

    service_instance_id             = var.service_instance_id
    rhcos_image_name                = var.rhcos_image_name
    processor_type                  = var.processor_type
    system_type                     = var.system_type
    network_name                    = var.network_name
    custom_bastion                  = var.custom_bastion
    custom_bastion_keypair          = var.custom_bastion_keypair
    bastion_ip                      = module.prepare.bastion_ip
    cluster_domain                  = var.cluster_domain
    cluster_id                      = local.cluster_id
    bootstrap                       = var.bootstrap
    master                          = var.master
    worker                          = var.worker
    master_volume_size              = var.master_volume_size
    worker_volume_size              = var.worker_volume_size
    volume_type                     = var.volume_type
    volume_shareable                = var.volume_shareable
}

module "install" {
    source                          = "./modules/5_install"

    service_instance_id             = var.service_instance_id
    network_name                    = var.network_name
    cluster_domain                  = var.cluster_domain
    cluster_id                      = local.cluster_id
    dns_forwarders                  = var.dns_forwarders
    bastion_ip                      = module.prepare.bastion_ip
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    ssh_agent                       = var.ssh_agent
    bastion_public_ip               = module.prepare.bastion_public_ip
    bootstrap_ip                    = module.nodes.bootstrap_ip
    master_ips                      = module.nodes.master_ips
    worker_ips                      = module.nodes.worker_ips
    bootstrap_mac                   = module.nodes.bootstrap_mac
    master_macs                     = module.nodes.master_macs
    worker_macs                     = module.nodes.worker_macs
    public_key                      = local.public_key
    pull_secret                     = file(coalesce(var.pull_secret_file, "/dev/null"))
    openshift_install_tarball       = var.openshift_install_tarball
    openshift_client_tarball        = var.openshift_client_tarball
    storage_type                    = var.storage_type
    release_image_override          = var.release_image_override
    enable_local_registry           = var.enable_local_registry
    local_registry_image            = var.local_registry_image
    ocp_release_tag                 = var.ocp_release_tag
    ocp_release_name                = var.ocp_release_name
    setup_squid_proxy               = var.setup_squid_proxy
    proxy                           = var.proxy
    helpernode_repo                 = var.helpernode_repo
    helpernode_tag                  = var.helpernode_tag
    install_playbook_repo           = var.install_playbook_repo
    install_playbook_tag            = var.install_playbook_tag
    log_level                       = var.installer_log_level
    ansible_extra_options           = var.ansible_extra_options
    rhcos_kernel_options            = var.rhcos_kernel_options
    upgrade_image                   = var.upgrade_image
    upgrade_pause_time              = var.upgrade_pause_time
    upgrade_delay_time              = var.upgrade_delay_time
}
