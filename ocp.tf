provider "ibm" {
    ibmcloud_api_key = var.ibmcloud_api_key
    region           = var.ibmcloud_region
    zone             = var.ibmcloud_zone
}

resource "random_id" "label" {
    byte_length = "2" # Since we use the hex, the word lenght would double
    prefix = "${var.cluster_id_prefix}-"
}

module "prepare" {
    source                          = "./modules/1_prepare"

    bastion                         = var.bastion
    service_instance_id             = var.service_instance_id
    cluster_id                      = "${random_id.label.hex}"
    cluster_domain                  = var.cluster_domain
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
    proxy                           = var.proxy
}

module "nodes" {
    source                          = "./modules/4_nodes"

    service_instance_id             = var.service_instance_id
    rhcos_image_name                = var.rhcos_image_name
    processor_type                  = var.processor_type
    system_type                     = var.system_type
    network_name                    = var.network_name
    bastion_ip                      = module.prepare.bastion_ip
    cluster_domain                  = var.cluster_domain
    cluster_id                      = "${random_id.label.hex}"
    bootstrap                       = var.bootstrap
    master                          = var.master
    worker                          = var.worker
}

module "install" {
    source                          = "./modules/5_install"

    service_instance_id             = var.service_instance_id
    network_name                    = var.network_name
    cluster_domain                  = var.cluster_domain
    cluster_id                      = "${random_id.label.hex}"
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
