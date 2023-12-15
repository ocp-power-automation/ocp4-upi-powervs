provider "ibm" {
  ibmcloud_api_key = var.ibmcloud_api_key
  region           = var.ibmcloud_region
  zone             = var.ibmcloud_zone
}

provider "ibm" {
  alias            = "vpc"
  region           = local.iaas_vpc_region
  ibmcloud_api_key = var.ibmcloud_api_key
}

resource "random_id" "label" {
  count       = var.cluster_id == "" ? 1 : 0
  byte_length = "2" # Since we use the hex, the word length would double
  prefix      = "${var.cluster_id_prefix}-"
}

locals {
  # Generates cluster_id as combination of cluster_id_prefix + (random_id or user-defined cluster_id)
  cluster_id   = var.cluster_id == "" ? random_id.label[0].hex : (var.cluster_id_prefix == "" ? var.cluster_id : "${var.cluster_id_prefix}-${var.cluster_id}")
  name_prefix  = var.use_zone_info_for_names ? "${local.cluster_id}-${var.ibmcloud_zone}-" : "${local.cluster_id}-"
  node_prefix  = var.use_zone_info_for_names ? "${var.ibmcloud_zone}-" : ""
  storage_type = lookup(var.bastion, "count", 1) > 1 ? "none" : var.storage_type
  powervs_vpc_region_map = {
    syd     = "au-syd",
    osa     = "jp-osa",
    tok     = "jp-tok",
    eu-de   = "eu-de",
    lon     = "eu-gb",
    tor     = "ca-tor",
    dal     = "us-south",
    sao     = "br-sao",
    us-east = "us-east"
  }
}

module "prepare" {
  source = "./modules/1_prepare"

  bastion                         = var.bastion
  service_instance_id             = var.service_instance_id
  cluster_id                      = local.cluster_id
  name_prefix                     = local.name_prefix
  node_prefix                     = local.node_prefix
  cluster_domain                  = var.cluster_domain
  rhel_image_name                 = var.rhel_image_name
  processor_type                  = var.processor_type
  system_type                     = var.system_type
  network_name                    = var.network_name
  network_dns                     = var.dns_forwarders == "" ? [] : [for dns in split(";", var.dns_forwarders) : trimspace(dns)]
  bastion_health_status           = var.bastion_health_status
  private_network_mtu             = var.private_network_mtu
  rhel_username                   = var.rhel_username
  private_key                     = local.private_key
  public_key                      = local.public_key
  ssh_agent                       = var.ssh_agent
  connection_timeout              = var.connection_timeout
  rhel_subscription_username      = var.rhel_subscription_username
  rhel_subscription_password      = var.rhel_subscription_password
  rhel_subscription_org           = var.rhel_subscription_org
  rhel_subscription_activationkey = var.rhel_subscription_activationkey
  ansible_repo_name               = var.ansible_repo_name
  rhel_smt                        = var.rhel_smt
  storage_type                    = local.storage_type
  volume_size                     = var.volume_size
  volume_shareable                = var.volume_shareable
  setup_squid_proxy               = var.use_ibm_cloud_services ? false : var.setup_squid_proxy
  proxy                           = var.proxy
  fips_compliant                  = var.fips_compliant
  create_cloud_connection         = local.create_cloud_connection
}

data "ibm_pi_workspace" "workspace" {
  pi_cloud_instance_id = var.service_instance_id
}

locals {
  is_per                  = contains(["dal10", "wdc06"], var.ibmcloud_zone)
  create_cloud_connection = var.use_ibm_cloud_services && var.ibm_cloud_connection_name == "" && !local.is_per
  tgw_network             = module.prepare.cloud_connection_name == "" ? data.ibm_pi_workspace.workspace.pi_workspace_details.crn : module.prepare.cloud_connection_name
}

module "nodes" {
  source = "./modules/4_nodes"

  service_instance_id             = var.service_instance_id
  rhcos_image_name                = var.rhcos_image_name
  processor_type                  = var.processor_type
  system_type                     = var.system_type
  network_name                    = var.network_name
  bastion_ip                      = lookup(var.bastion, "count", 1) > 1 ? module.prepare.bastion_vip : module.prepare.bastion_ip[0]
  cluster_domain                  = var.cluster_domain
  cluster_id                      = local.cluster_id
  name_prefix                     = local.name_prefix
  node_prefix                     = local.node_prefix
  bootstrap                       = var.bootstrap
  master                          = var.master
  worker                          = var.worker
  volume_shareable                = var.volume_shareable
  bastion_external_vip            = module.prepare.bastion_external_vip
  bastion_public_ip               = module.prepare.bastion_public_ip
  rhel_username                   = var.rhel_username
  private_key                     = local.private_key
  ssh_agent                       = var.ssh_agent
  rhcos_import_image              = var.rhcos_import_image
  rhcos_import_bucket_region      = lookup(local.powervs_vpc_region_map, var.ibmcloud_region, "au-syd")
  rhcos_import_image_filename     = var.rhcos_import_image_filename
  rhcos_import_image_storage_type = var.rhcos_import_image_storage_type
}

module "install" {
  source     = "./modules/5_install"
  depends_on = [module.nodes]

  service_instance_id            = var.service_instance_id
  region                         = var.ibmcloud_region
  zone                           = var.ibmcloud_zone
  system_type                    = var.system_type
  cluster_domain                 = module.nodes.cluster_domain
  cluster_id                     = local.cluster_id
  name_prefix                    = local.name_prefix
  node_prefix                    = local.node_prefix
  fips_compliant                 = var.fips_compliant
  dns_forwarders                 = var.dns_forwarders
  gateway_ip                     = module.prepare.gateway_ip
  cidr                           = module.prepare.cidr
  public_cidr                    = module.prepare.public_cidr
  bastion_count                  = lookup(var.bastion, "count", 1)
  bastion_vip                    = module.prepare.bastion_vip
  bastion_ip                     = module.prepare.bastion_ip
  rhel_username                  = var.rhel_username
  private_key                    = local.private_key
  ssh_agent                      = var.ssh_agent
  connection_timeout             = var.connection_timeout
  bastion_internal_vip           = module.prepare.bastion_internal_vip
  bastion_external_vip           = module.prepare.bastion_external_vip
  bastion_public_ip              = module.prepare.bastion_public_ip
  bootstrap_ip                   = module.nodes.bootstrap_ip
  master_ips                     = module.nodes.master_ips
  worker_ips                     = module.nodes.worker_ips
  bootstrap_mac                  = module.nodes.bootstrap_mac
  master_macs                    = module.nodes.master_macs
  worker_macs                    = module.nodes.worker_macs
  master_ids                     = module.nodes.master_ids
  worker_ids                     = module.nodes.worker_ids
  public_key                     = local.public_key
  pull_secret                    = file(coalesce(var.pull_secret_file, "/dev/null"))
  openshift_install_tarball      = var.openshift_install_tarball
  openshift_client_tarball       = var.openshift_client_tarball
  storage_type                   = local.storage_type
  release_image_override         = var.release_image_override
  private_network_mtu            = var.private_network_mtu
  enable_local_registry          = var.enable_local_registry
  local_registry_image           = var.local_registry_image
  ocp_release_tag                = var.ocp_release_tag
  ocp_release_name               = var.ocp_release_name
  setup_snat                     = var.use_ibm_cloud_services ? true : var.setup_snat
  setup_squid_proxy              = var.use_ibm_cloud_services ? false : var.setup_squid_proxy
  proxy                          = var.proxy
  helpernode_repo                = var.helpernode_repo
  helpernode_tag                 = var.helpernode_tag
  install_playbook_repo          = var.install_playbook_repo
  install_playbook_tag           = var.install_playbook_tag
  log_level                      = var.installer_log_level
  ansible_extra_options          = var.ansible_extra_options
  rhcos_pre_kernel_options       = var.rhcos_pre_kernel_options
  rhcos_kernel_options           = var.rhcos_kernel_options
  node_labels                    = var.node_labels
  chrony_config                  = var.chrony_config
  chrony_config_servers          = var.chrony_config_servers
  upgrade_image                  = var.upgrade_image
  upgrade_version                = var.upgrade_version
  upgrade_pause_time             = var.upgrade_pause_time
  upgrade_delay_time             = var.upgrade_delay_time
  eus_upgrade_version            = var.eus_upgrade_version
  eus_upgrade_channel            = var.eus_upgrade_channel
  eus_upgrade_image              = var.eus_upgrade_image
  eus_upstream                   = var.eus_upstream
  ibm_cloud_dl_endpoint_net_cidr = var.ibm_cloud_dl_endpoint_net_cidr
  ibm_cloud_http_proxy           = var.ibm_cloud_http_proxy
  cni_network_provider           = var.cni_network_provider
  use_ibm_cloud_services         = var.use_ibm_cloud_services
  ibmcloud_api_key               = var.ibmcloud_api_key
  csi_driver_install             = var.csi_driver_install
  csi_driver_type                = var.csi_driver_type
  csi_driver_version             = var.csi_driver_version
  vpc_cidr                       = var.use_ibm_cloud_services ? module.ibmcloud[0].vpc_cidr : ""
  luks_compliant                 = var.luks_compliant
  luks_config                    = var.luks_config
  luks_filesystem_device         = var.luks_filesystem_device
  luks_format                    = var.luks_format
  luks_wipe_filesystem           = var.luks_wipe_filesystem
  luks_device                    = var.luks_device
  luks_label                     = var.luks_label
  luks_options                   = var.luks_options
  luks_wipe_volume               = var.luks_wipe_volume
  luks_name                      = var.luks_name
  bootstrap_count                = var.bootstrap["count"]
  master_count                   = var.master["count"]
  worker_count                   = var.worker["count"]
  kdump_enable                   = var.kdump_enable
  kdump_commandline_remove       = var.kdump_commandline_remove
  kdump_commandline_append       = var.kdump_commandline_append
  kdump_kexec_args               = var.kdump_kexec_args
  kdump_img                      = var.kdump_img
  kdump_log_path                 = var.kdump_log_path
  kdump_crash_kernel_memory      = var.kdump_crash_kernel_memory
}

module "ibmcloud" {
  count  = var.use_ibm_cloud_services ? 1 : 0
  source = "./modules/7_ibmcloud"
  providers = {
    ibm = ibm.vpc
  }

  cluster_domain           = module.nodes.cluster_domain
  cluster_id               = local.cluster_id
  name_prefix              = local.name_prefix
  node_prefix              = local.node_prefix
  bastion_count            = lookup(var.bastion, "count", 1)
  bootstrap_count          = var.bootstrap["count"]
  master_count             = var.master["count"]
  worker_count             = var.worker["count"]
  bastion_vip              = module.prepare.bastion_vip
  bastion_ip               = module.prepare.bastion_ip
  bootstrap_ip             = module.nodes.bootstrap_ip
  master_ips               = module.nodes.master_ips
  worker_ips               = module.nodes.worker_ips
  vpc_name                 = var.ibm_cloud_vpc_name
  vpc_subnet_name          = var.ibm_cloud_vpc_subnet_name
  vpc_region               = local.iaas_vpc_region
  ibm_cloud_resource_group = var.ibm_cloud_resource_group
  ibm_cloud_cis_crn        = var.ibm_cloud_cis_crn
  ibm_cloud_tgw            = var.ibm_cloud_tgw
  ibm_cloud_tgw_net        = local.tgw_network
  is_per                   = local.is_per
  is_new_cloud_connection  = local.create_cloud_connection
}

module "custom" {
  count      = var.ibm_cloud_cis_crn != "" && !var.use_ibm_cloud_services ? 1 : 0
  source     = "./modules/8_custom"
  depends_on = [module.install]

  cluster_domain    = module.nodes.cluster_domain
  cluster_id        = local.cluster_id
  bastion_public_ip = lookup(var.bastion, "count", 1) > 1 ? module.prepare.bastion_external_vip : module.prepare.bastion_public_ip[0]
  ibm_cloud_cis_crn = var.ibm_cloud_cis_crn
}
