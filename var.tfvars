### Configure the IBM Cloud provider
ibmcloud_api_key    = "<key>"
ibmcloud_region     = "<region>"
ibmcloud_zone       = ""
service_instance_id = "<cloud_instance_ID>"

### Configure the Instance details
### This is default minimalistic config. For PowerVS processors are equal to entitled physical count
### So N processors == N physical core entitlements == ceil[N] vCPUs.
### Example 0.5 processors == 0.5 physical core entitlements == ceil[0.5] = 1 vCPU == 8 logical OS CPUs (SMT=8)
### Example 1.5 processors == 1.5 physical core entitlements == ceil[1.5] = 2 vCPU == 16 logical OS CPUs (SMT=8)
### Example 2 processors == 2 physical core entitlements == ceil[2] = 2 vCPU == 16 logical OS CPUs (SMT=8)
bastion                     = {memory      = "16",   processors  = "1"}
bootstrap                   = {memory      = "16",   processors  = "0.5",  "count"   = 1}
master                      = {memory      = "16",   processors  = "0.5",  "count"   = 3}
worker                      = {memory      = "16",   processors  = "0.5",  "count"   = 2}
## change below variables as per your environment
rhel_image_name     = "rhel-8.2"       #Default RHEL boot image name imported into PowerVS service instance
rhcos_image_name    = "rhcos-4.5.4"    #Default RHCOS boot image name imported into PowerVS service instance
processor_type      = "shared"
system_type         = "s922"
network_name        = "ocp-net"        #Private network created in PowerVS service instance

rhel_username               = "root"
public_key_file             = "data/id_rsa.pub"  #Replace with correct key file
private_key_file            = "data/id_rsa"
private_key                 = ""
public_key                  = ""
rhel_subscription_username  = ""
rhel_subscription_password  = ""
rhel_smt                    = 4


### OpenShift variables
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/4.5.4/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/4.5.4/openshift-client-linux.tar.gz"

#release_image_override     = ""

pull_secret_file            = "data/pull-secret.txt" #Replace with correct pull-secret.txt

cluster_domain              = "ibm.com"  #Set domain to nip.io or xip.io if you prefer using online wildcard domain and avoid modifying /etc/hosts
cluster_id_prefix           = "test"     #Change it as required
cluster_id                  = ""

### Local registry variables
enable_local_registry       = false  #Set to true to enable usage of local registry for restricted network install.

#local_registry_image       = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
#ocp_release_tag            = "4.4.9-ppc64le"
#ocp_release_name           = "ocp-release"

### Additional Variables


#helpernode_repo             = "https://github.com/RedHatOfficial/ocp4-helpernode"
#helpernode_tag             = "5eab3db53976bb16be582f2edc2de02f7510050d"
#install_playbook_repo       = "https://github.com/ocp-power-automation/ocp4-playbooks"
#install_playbook_tag       = "02a598faa332aa2c3d53e8edd0e840440ff74bd5"

installer_log_level         = "info"
ansible_extra_options       = "-v"
dns_forwarders              = "1.1.1.1; 9.9.9.9"
rhcos_kernel_options        = []
chrony_config               = true
#chrony_config_servers      = [ {server = "0.centos.pool.ntp.org", options = "iburst"}, {server = "1.centos.pool.ntp.org", options = "iburst"} ]

## Set up a squid proxy server on the bastion node.
setup_squid_proxy           = true

## Uncomment any one of the below formats to use external proxy. Default 'port' will be 3128 if not specified. Not authenticated if 'user' is not specified.
## These values should remain commented when `setup_squid_proxy = true`
## Set `setup_squid_proxy = false` when using external proxy.
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

