### Configure the IBM Cloud provider
ibmcloud_api_key    = "<key>"
ibmcloud_region     = "<region>"
ibmcloud_zone       = ""
service_instance_id = "<cloud_instance_ID>"

### Configure the Custom Bastion Instance details
#custom_bastion                = false  #Set to true to use custom bastion instance
#custom_bastion_name           = ""
#custom_bastion_key_pair       = ""
#custom_bastion_public_network = ""
#custom_bastion_volume_size    = "" # Value in GB

### Configure the Instance details
bastion                     = {memory      = "8",   processors  = "1"}
bootstrap                   = {memory      = "16",   processors  = "2",  "count"   = 1}
master                      = {memory      = "16",   processors  = "2",  "count"   = 3}
worker                      = {memory      = "16",   processors  = "2",  "count"   = 2}
## change below variables as per your environment
rhel_image_name     = "rhel-8.2"
rhcos_image_name    = "rhcos-4.4.9"
processor_type      = "shared"
system_type         = "s922"
network_name        = "ocp-net"

rhel_username               = "root"
public_key_file             = "~/.ssh/id_rsa.pub"
private_key_file            = "~/.ssh/id_rsa"
private_key                 = ""
public_key                  = ""
rhel_subscription_username  = ""
rhel_subscription_password  = ""


### OpenShift variables
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.4/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.4/openshift-client-linux.tar.gz"

#release_image_override     = ""

cluster_domain              = "ibm.com"
cluster_id_prefix           = "test"

### Local registry variables
enable_local_registry       = false  #Set to true to enable usage of local registry for restricted network install.

#local_registry_image       = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
#ocp_release_tag            = "4.4.9-ppc64le"
#ocp_release_name           = "ocp-release"

### Instrumentation


#helpernode_repo             = "https://github.com/RedHatOfficial/ocp4-helpernode"
#helpernode_tag             = "5eab3db53976bb16be582f2edc2de02f7510050d"
#install_playbook_repo       = "https://github.com/ocp-power-automation/ocp4-playbooks"
#install_playbook_tag       = "f5c25c1722cb9d7edec2a42936be19649a9c77b3"

installer_log_level         = "info"
ansible_extra_options       = "-v"
pull_secret_file            = "data/pull-secret.txt"
dns_forwarders              = "1.1.1.1; 9.9.9.9"
rhcos_kernel_options        = []


## Set up a squid proxy server on the bastion node.
setup_squid_proxy           = true

## N/A when `setup_squid_proxy = true`, set `setup_squid_proxy = false` when using external proxy.
## Uncomment any one of the below formats to use external proxy. Default 'port' will be 3128 if not specified. Not authenticated if 'user' is not specified.
#proxy = {}
#proxy = {server = "hostname_or_ip"}
#proxy = {server = "hostname_or_ip", port = "3128", user = "pxuser", password = "pxpassword"}


storage_type                = "nfs"
volume_size                 = "300" # Value in GB
volume_type                 = "tier3"
volume_shareable            = false
## Uncomment if you need to attach data volume to the master/worker nodes
#master_volume_size          = "500"
#worker_volume_size          = "500"

#upgrade_image = ""
#upgrade_pause_time = "90"
#upgrade_delay_time = "600"

