### Configure the IBM Cloud provider
ibmcloud_api_key    = "<key>"
ibmcloud_region     = "<region>"
ibmcloud_zone       = ""
service_instance_id = "<cloud_instance_ID>"

### Configure the Instance details
bastion                     = {memory      = "8",   processors  = "1"}
bootstrap                   = {memory      = "16",   processors  = "2",  "count"   = 1}
master                      = {memory      = "16",   processors  = "2",  "count"   = 3}
worker                      = {memory      = "16",   processors  = "2",  "count"   = 2}
rhel_image_name     = "rhel-8.2"
rhcos_image_name    = "rhcos-4.4.9"
processor_type      = "shared"
system_type         = "s922"
network_name        = "my_network_name"

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

cluster_domain              = "example.com"
cluster_id_prefix           = "test"


### Instrumentation


#helpernode_repo             = "https://github.com/RedHatOfficial/ocp4-helpernode"
#helpernode_tag             = "fddbbc651153ef2966e5cb4d4167990b31c01ceb"
#install_playbook_repo       = "https://github.com/ocp-power-automation/ocp4-playbooks"
#install_playbook_tag       = "47b1fc6caa69f3705419889a9ea47717ec3d8c2e"

installer_log_level         = "info"
ansible_extra_options       = "-v"
pull_secret_file            = "data/pull-secret.txt"
dns_forwarders              = "1.1.1.1; 9.9.9.9"
rhcos_kernel_options        = []

## Uncomment any one of the below formats to use proxy. Default 'port' will be 3128 if not specified. Not authenticated if 'user' is not specified.
#proxy = {}
#proxy = {server = "hostname_or_ip"}
#proxy = {server = "hostname_or_ip", port = "3128", user = "pxuser", password = "pxpassword"}


storage_type                = "nfs"
volume_size                 = "300" # Value in GB
volume_type                 = "tier3"

#upgrade_image = ""
#upgrade_pause_time = "90"
#upgrade_delay_time = "600"

