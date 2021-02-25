### IBM Cloud details

ibmcloud_api_key            = "<key>"
ibmcloud_region             = "<region>"
ibmcloud_zone               = "<zone>"
service_instance_id         = "<cloud_instance_ID>"

### OpenShift Cluster Details

### This is default minimalistic config. For PowerVS processors are equal to entitled physical count
### So N processors == N physical core entitlements == ceil[N] vCPUs.
### Example 0.5 processors == 0.5 physical core entitlements == ceil[0.5] = 1 vCPU == 8 logical OS CPUs (SMT=8)
### Example 1.5 processors == 1.5 physical core entitlements == ceil[1.5] = 2 vCPU == 16 logical OS CPUs (SMT=8)
### Example 2 processors == 2 physical core entitlements == ceil[2] = 2 vCPU == 16 logical OS CPUs (SMT=8)
bastion                     = {memory      = "16",   processors  = "1",    "count"   = 1}
bootstrap                   = {memory      = "32",   processors  = "0.5",  "count"   = 1}
master                      = {memory      = "32",   processors  = "0.5",  "count"   = 3}
worker                      = {memory      = "32",   processors  = "0.5",  "count"   = 2}

rhel_image_name             = "rhel-8.3"
rhcos_image_name            = "rhcos-4.7"
processor_type              = "shared"
system_type                 = "s922"
network_name                = "ocp-net"

rhel_username               = "root"
public_key_file             = "data/id_rsa.pub"
private_key_file            = "data/id_rsa"
rhel_subscription_username  = "<subscription-id>"          #Leave this as-is if using CentOS as bastion image
rhel_subscription_password  = "<subscription-password>"    #Leave this as-is if using CentOS as bastion image
rhel_subscription_org           = ""                       # Define it only when using activationkey for RHEL subscription
rhel_subscription_activationkey = ""                       # Define it only when using activationkey for RHEL subscription
rhel_smt                    = 4

### OpenShift Installation Details

openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.7/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.7/openshift-client-linux.tar.gz"
pull_secret_file            = "data/pull-secret.txt"

cluster_domain              = "ibm.com"  #Set domain to nip.io or xip.io if you prefer using online wildcard domain and avoid modifying /etc/hosts
cluster_id_prefix           = "test-ocp"
cluster_id                  = ""


### Misc Customizations

#enable_local_registry      = false  #Set to true to enable usage of local registry for restricted network install.
#local_registry_image       = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
#ocp_release_tag            = "4.4.9-ppc64le"
#ocp_release_name           = "ocp-release"
#release_image_override     = ""


#helpernode_repo            = "https://github.com/RedHatOfficial/ocp4-helpernode"
#helpernode_tag             = ""
#install_playbook_repo      = "https://github.com/ocp-power-automation/ocp4-playbooks"
#install_playbook_tag       = ""

#installer_log_level        = "info"
#ansible_extra_options      = "-v"
#ansible_repo_name          = "ansible-2.9-for-rhel-8-ppc64le-rpms"
#dns_forwarders             = "1.1.1.1; 9.9.9.9"
#rhcos_kernel_options       = []
#chrony_config              = true
#chrony_config_servers      = [ {server = "0.centos.pool.ntp.org", options = "iburst"}, {server = "1.centos.pool.ntp.org", options = "iburst"} ]

#setup_squid_proxy          = true

## N/A when `setup_squid_proxy = true`, set `setup_squid_proxy = false` when using external proxy.
#proxy                      = {server = "hostname_or_ip", port = "3128", user = "pxuser", password = "pxpassword"}


#storage_type               = "nfs"
#volume_size                = "300"    #Value in GB
#volume_type                = "tier3"
#volume_shareable           = false

#master_volume_size         = "500"   #Value in GB
#worker_volume_size         = "500"   #Value in GB

#upgrade_version            = ""
#upgrade_pause_time         = "70"
#upgrade_delay_time         = "600"

#ibm_cloud_dl_endpoint_net_cidr = ""  #Set this to IBM Cloud DirectLink endpoint network cidr eg. 10.0.0.0/8
#ibm_cloud_http_proxy = ""            #Set this to IBM Cloud http/squid proxy eg. http://10.166.13.64:3128

#cni_network_provider       = "OpenshiftSDN"
