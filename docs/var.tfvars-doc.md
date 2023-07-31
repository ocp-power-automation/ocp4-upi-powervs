# How to use var.tfvars

- [How to use var.tfvars](#how-to-use-vartfvars)
  - [Introduction](#introduction)
    - [IBM Cloud Details](#ibm-cloud-details)
    - [OpenShift Cluster Details](#openshift-cluster-details)
    - [OpenShift Installation Details](#openshift-installation-details)
    - [Misc Customizations](#misc-customizations)


## Introduction

This guide gives an overview of the various terraform variables that are used for the deployment.
The default values are set in [variables.tf](../variables.tf)

### IBM Cloud Details

These set of variables specify the access key and PowerVS location details.
```
ibmcloud_api_key    = "xyzaaaaaaaabcdeaaaaaa"
ibmcloud_region     = "xya"
ibmcloud_zone       = "abc"
service_instance_id = "abc123xyzaaaa"
```
You'll need to create an API key to use the automation code. Please refer to the following instructions to generate API key - https://cloud.ibm.com/docs/account?topic=account-userapikey

In order to retrieve the PowerVS region, zone and instance specific details please use the IBM Cloud CLI.

1. Run `ibmcloud pi service-list`. It will list the service instance names with IDs.
2. The ID will be of the form
   ```
   crn:v1:bluemix:public:power-iaas:eu-de-1:a/65b64c1f1c29460e8c2e4bbfbd893c2c:360a5df8-3f00-44b2-bd9f-d9a51fe53de6::
   ```
3. The **6th** field is the **ibmcloud_zone** and **8th** field is the **service_instance_id**
   ```
   $ echo "crn:v1:bluemix:public:power-iaas:eu-de-1:a/65b64c1f1c29460e8c2e4bbfbd893c2c:360a5df8-3f00-44b2-bd9f-d9a51fe53de6::" | cut -f6,8 -d":"
   eu-de-1:360a5df8-3f00-44b2-bd9f-d9a51fe53de6
   ```

   Following are the region and zone mapping:

   | ibmcloud_region | ibmcloud_zone  |
   |-----------------|----------------|
   | eu-de           | eu-de-1        |
   | eu-de           | eu-de-2        |
   | dal             | dal12          |
   | lon             | lon04          |
   | lon             | lon06          |
   | syd             | syd04          |
   | sao             | sao01          |
   | tor             | tor01          |
   | tok             | tok04          |
   | us-east         | us-east        |

   NOTE:  us-east is Washington, DC datacenter.

   Tieing all these, the values to be used will be as shown below:
   ```
   ibmcloud_region     = eu-de
   ibmcloud_zone       = eu-de-1
   service_instance_id = 360a5df8-3f00-44b2-bd9f-d9a51fe53de6
   ```


### OpenShift Cluster Details

These set of variables specify the cluster capacity.

Change the values as per your requirement.
The defaults (recommended config) should suffice for most of the common use-cases.
```
bastion     = {memory      = "16",   processors  = "1",    "count"   = 1}
bootstrap   = {memory      = "32",   processors  = "0.5",  "count"   = 1}
master      = {memory      = "32",   processors  = "0.5",  "count"   = 3}
worker      = {memory      = "32",   processors  = "0.5",  "count"   = 2}
```

You can also choose one of the default node configuration templates that are stored in the `compute-vars` directory, as per your requirements.
The default flavors present under the compute-vars folder:
   ```
   small.tfvars
   medium.tfvars
   large.tfvars
   ```

`memory` is in `GBs` and `count` specifies the number of VMs that should be created for each type.

To enable high availability (HA) for cluster services running on the bastion set the bastion `count` value to 2.
Note that in case of HA, the automation will not setup NFS storage. `count` of 1 for bastion implies the default non-HA bastion setup.

You can optionally set the worker `count` value to 0 in which case all the cluster pods will be running on the master/supervisor nodes.
Ensure you use proper sizing for master/supervisor nodes to avoid resource starvation for containers.

To attach additional volumes to master or worker nodes, set the optional `data_volume_count` key to the number of volumes that is to be attached and the `data_volume_size` to the size (in GB) for each volume.
```
master      = {memory      = "32",   processors  = "0.5",  "count"   = 3, data_volume_count  = 0, data_volume_size  = 100}
worker      = {memory      = "32",   processors  = "0.5",  "count"   = 2, data_volume_count  = 0, data_volume_size  = 100}
```

For PowerVS processors are equal to entitled physical count. So **N** processors == **N** physical core entitlements == **ceil[N]** vCPUs.
Here are some examples to help you understand the relationship.

- Example 1
  ```
  0.5 processors == 0.5 physical core entitlements == ceil[0.5] = 1 vCPU == 8 logical OS CPUs (SMT=8)
  ```
- Example 2
  ```
  1.5 processors == 1.5 physical core entitlements == ceil[1.5] = 2 vCPU == 16 logical OS CPUs (SMT=8)
  ```
- Example 3
  ```
  2 processors == 2 physical core entitlements == ceil[2] = 2 vCPU == 16 logical OS CPUs (SMT=8)
  ```

These set of variables specify the RHEL and RHCOS boot image names. These images should have been already imported in your PowerVS service instance.
Change the image names according to your environment. Ensure that you use the correct RHCOS image specific to the pre-release version
```
rhel_image_name     = "<rhel_or_centos_image-name>"
rhcos_image_name    = "<rhcos-image-name>"
```
Note that the boot images should have a minimum disk size of 120GB

These set of variables should be provided when RHCOS image should be imported from public bucket of cloud object storage to your PowerVS service instance
```
rhcos_import_image              = true                                                   # true/false (default=false)
rhcos_import_image_filename     = "rhcos-411-85-202203181612-0-ppc64le-powervs.ova.gz"   # RHCOS boot image file name available in cloud object storage
rhcos_import_image_storage_type = "tier1"                                                # tier1/tier3 (default=tier1) Storage type in PowerVS where image needs to be uploaded
```

This variable specifies the name of the private network that is configured in your PowerVS service instance.
```
network_name        = "ocp-net"
```

These set of variables specify the type of processor and physical system type to be used for the VMs.
Change the default values according to your requirement.
```
processor_type      = "shared"  # Can be shared, dedicated or capped
system_type         = "s922"    # Run IBM Cloud CLI command 'ibmcloud pi system-pool' for available options in your location
```

These set of variables specify the username and the SSH key to be used for accessing the bastion node.
```
rhel_username               = "root"  #Set it to an appropriate username for non-root user access
public_key_file             = "data/id_rsa.pub"
private_key_file            = "data/id_rsa"
```
rhel_username is set to root. rhel_username can be set to an appropriate username having superuser privileges with no password prompt.
Please note that only OpenSSH formatted keys are supported. Refer to the following links for instructions on creating SSH key based on your platform.
- Windows 10 - https://phoenixnap.com/kb/generate-ssh-key-windows-10
- Mac OSX - https://www.techrepublic.com/article/how-to-generate-ssh-keys-on-macos-mojave/
- Linux - https://www.siteground.com/kb/generate_ssh_key_in_linux/

Create the SSH key-pair and keep it under the `data` directory

These set of variables specify the RHEL subscription details, RHEL subscription supports two methods: one is using username and password, the other is using activation key.
This is sensitive data, and if you don't want to save it on disk, use environment variables `RHEL_SUBS_USERNAME` and `RHEL_SUBS_PASSWORD` and pass them to `terraform apply` command as shown in the [Quickstart guide](./quickstart.md#setup-terraform-variables).
If you are using CentOS as the bastion image, then leave these variables as-is.

```
rhel_subscription_username  = "user@test.com"
rhel_subscription_password  = "mypassword"
```
Or define following variables to use activation key for RHEL subscription:
```
rhel_subscription_org = "org-id"
rhel_subscription_activationkey = "activation-key"
```

This variable specifies the number of hardware threads (SMT) that's used for the bastion node.
Default setting should be fine for majority of the use-cases.

```
rhel_smt                    = 4
```

### OpenShift Installation Details

These variables specify the URL for the OpenShift installer and client binaries.
Change the URL to the specific stable or pre-release version that you want to install on PowerVS.
Reference link - `https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/`

For latest stable:
```
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-client-linux.tar.gz"
```
For specific stable version:
```
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.12/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.12/openshift-client-linux.tar.gz"
```
For pre-release:
```
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-client-linux.tar.gz"
```

This variable specifies the OpenShift pull secret. This is available from the following link -  https://cloud.redhat.com/openshift/install/power/user-provisioned
Download the secret and copy it to `data/pull-secret.txt`.
```
pull_secret_file            = "data/pull-secret.txt"
```

These variables specifies the OpenShift cluster domain details.
Edit it as per your requirements.
```
cluster_domain              = "ibm.com"
cluster_id_prefix           = "test-ocp"
cluster_id                  = ""

use_zone_info_for_names  = true
```
Set the `cluster_domain` to `nip.io`, `xip.io` or `sslip.io` if you prefer using online wildcard domains.
Default is `ibm.com`.
The `cluster_id_prefix` should not be more than 8 characters. Nodes are pre-fixed with this value.
Default value is `test-ocp`
If `cluster_id_prefix` is not set, the `cluster_id` will be used only without prefix.

A random value will be used for `cluster_id` if not set.
The total length of `cluster_id_prefix`.`cluster_id` should not exceed 32 characters.

The `use_zone_info_for_names` is a flag to indicate whether to use `cluster_id`-`ibmcloud_zone` or only `cluster_id` as name prefix for resource naming on PowerVS. The default value is set to `true` to use zone info in names, and the total length of `cluster_id_prefix`-`cluster_id`-`ibmcloud_zone` should not exceed 32 characters.

### FIPS Variable for OpenShift deployment

These variables will be used for deploying OCP in FIPS mode.
Change the values as per your requirement.
```
fips_compliant      = false
```
Note: Once fips_compliant set to true it will enable FIPS on the OCP cluster and also on bastion nodes. At the end of install the bastion nodes will be rebooted.

### Using IBM Cloud Services

You can use IBM Cloud classic DNS and VPC Load Balancer services for running the OCP cluster. When this feature is enabled the services called named (DNS) and haproxy (Load Balancer) will not be running on the bastion/helpernode.

Ensure you have setup [DirectLink](https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-ordering-direct-link-connect) with IBM Cloud VPC over the private network in cloud instance. Also, ensure you have registered a [DNS](https://cloud.ibm.com/docs/dns?topic=dns-register-a-new-domain) domain and use it as given in `cluster_domain` variable.

**IMPORTANT**: This is an **experimental** feature at present. Please manually set variables `setup_snat = true` and `setup_squid_proxy = false` for using IBM Cloud services. This will allow the cluster nodes have public internet access without a proxy server.

Below variables needs to be set in order to use the IBM Cloud services.

```
use_ibm_cloud_services    = true
ibm_cloud_vpc_name        = "ocp-vpc"
ibm_cloud_vpc_subnet_name = "ocp-subnet"
```

These set of variables specify the username and API key for accessing IBM Cloud services. The default combination should suffice for most of the common use-cases.

```
iaas_classic_username     = "apikey"
iaas_classic_api_key      = "" # if empty, will default to ibmcloud_api_key.
iaas_vpc_region           = "" # if empty, will default to ibmcloud_region.
```

Note: `iaas_classic_username`, `iaas_classic_api_key` and `iaas_vpc_region` variables are optional, These variables need to be set only when using a different classic username, key and vpc region. By default `apikey` will be used as the `iaas_class_username`, `ibmcloud_api_key` will be used as the `iaas_classic_api_key` and `ibmcloud_region` will be used as the `iaas_vpc_region`. Note that non-default values for these variables can also be passed via environment variables `IAAS_CLASSIC_USERNAME` and `IAAS_CLASSIC_API_KEY` respectively.


### Misc Customizations

These variables provides miscellaneous customizations. For common usage scenarios these are not required and should be left unchanged.

The following variables can be used for disconnected install by using a local mirror registry on the bastion node.

```
enable_local_registry      = false  #Set to true to enable usage of local registry for restricted network install.
local_registry_image       = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
ocp_release_tag            = "4.4.9-ppc64le"
ocp_release_name           = "ocp-release"
```

This variable can be used for trying out custom OpenShift install image for development use.
```
release_image_override     = ""
```

These variables specify the ansible playbooks that are used for OpenShift install and post-install customizations.
```
helpernode_repo            = "https://github.com/redhat-cop/ocp4-helpernode"
helpernode_tag             = "bf7842ec240f1d9ba5b5f9897bb72e7c86500faa"
install_playbook_repo      = "https://github.com/ocp-power-automation/ocp4-playbooks"
install_playbook_tag       = "main"
```

This variable specify if bastion should poll for the Health Status to be OK or WARNING. Default is OK.
```
bastion_health_status       = "OK"
```

This variable specify the MTU value for the private network interface on RHEL and RHCOS nodes. The CNI network will have <private_network_mtu> - 50 for OpenshiftSDN and <private_network_mtu> - 100 for OVNKubernetes network provider.
```
private_network_mtu         = 1450
```

These variables can be used when debugging ansible playbooks.
```
installer_log_level         = "info"
ansible_extra_options       = "-v"
```

This variable can be used to change the repository name for installing ansible package on RHEL.
```
ansible_repo_name           = "ansible-2.9-for-rhel-8-ppc64le-rpms"
```

This variable specifies the external DNS servers to forward DNS queries that cannot be resolved locally.
```
dns_forwarders              = "1.1.1.1; 9.9.9.9"
```

List of [day-1 kernel arguments](https://docs.openshift.com/container-platform/latest/installing/install_config/installing-customizing.html#installation-special-config-kargs_installing-customizing) for the cluster nodes.
To add kernel arguments to master or worker nodes, using MachineConfig object and inject that object into the set of manifest files used by Ignition during cluster setup. Use only if they are needed to complete the initial OCP installation. The automation will set `"rd.multipath=default"` and `"root=/dev/disk/by-label/dm-mpath-root"` by default.
```
rhcos_pre_kernel_options        = []
```
- Example 1
  ```
  rhcos_pre_kernel_options   =  ["loglevel=7"]
  ```

List of [kernel arguments](https://docs.openshift.com/container-platform/latest/post_installation_configuration/machine-configuration-tasks.html#nodes-nodes-kernel-arguments_post-install-machine-configur
ation-tasks) for the cluster nodes.
Note that this will be applied after the cluster is installed and all the nodes are in `Ready` status.
```
rhcos_kernel_options        = []
```
- Example 1
  ```
  rhcos_kernel_options      = ["slub_max_order=0","enforcing=0"]
  ```

This is a Map of [Node labels](https://kubernetes.io/docs/reference/labels-annotations-taints) and its values. Some of the well known labels such as `topology.kubernetes.io/region, topology.kubernetes.io/zone and node.kubernetes.io/instance-type` are automated. More custom labels can be added using the `node_labels` map variable.
Note that this will be applied after the cluster is installed and all the nodes are in `Ready` status.
```
node_labels            = {}
```
- Example 1
  ```
  node_labels = {"failure-domain.beta.kubernetes.io/region": "mon","failure-domain.beta.kubernetes.io/zone": "mon01"}
  ```

These are NTP specific variables that are used for time-synchronization in the OpenShift cluster.
```
chrony_config               = true
chrony_config_servers       = [ {server = "0.centos.pool.ntp.org", options = "iburst"}, {server = "1.centos.pool.ntp.org", options = "iburst"} ]
```

These set of variables are specific for cluster wide proxy configuration.
Public internet access for the OpenShift cluster nodes is via Squid proxy deployed on the bastion.
```
setup_squid_proxy           = true
```

If you have a separate proxy, and don't want to set the Squid proxy on bastion then use the following variables.
```
setup_squid_proxy           = false
proxy                       = {server = "hostname_or_ip", port = "3128", user = "pxuser", password = "pxpassword"}
```
Except `server` all other attributes are optional. Default `port` is `3128` with unauthenticated access.

These variables specify details about NFS storage that is setup by default on the bastion server.

```
storage_type                = "nfs"
volume_size                 = "300" # Value in GB
volume_shareable            = false
```

The following variables are specific to upgrading an existing installation.
```
upgrade_image      = ""  #(e.g. `"quay.io/openshift-release-dev/ocp-release-nightly@sha256:xxxxx"`)
upgrade_version    = ""
upgrade_pause_time = "70"
upgrade_delay_time = "600"
```
One of the two varaibles `upgrade_image` or `upgrade_version` is required for upgrading the cluster.
`upgrade_image` having higher precedence than `upgrade_version`.


The following variables are specific to performing EUS upgrades.

```
eus_upgrade_version        = "4.11.14"
eus_upgrade_channel        = "stable-4.11"  #(stable-4.x, fast-4.x, candidate-4.x, eus-4.x)
eus_upgrade_image          = "quay.io/openshift-release-dev/ocp-release:4.11.14-ppc64le"
eus_upstream               = "" (e.g. `"https://ppc64le.ocp.releases.ci.openshift.org/graph"`)
```

The following variables are specific to enable the connectivity between OCP nodes in PowerVS and IBM Cloud infrastructure over DirectLink.
```
ibm_cloud_dl_endpoint_net_cidr = ""
ibm_cloud_http_proxy = ""
```

This variable is used to set the default Container Network Interface (CNI) network provider such as OpenShiftSDN or OVNKubernetes

```
cni_network_provider       = "OVNKubernetes"
```

This variable is used to enable SNAT for OCP nodes. When using SNAT, the OCP nodes will be able to access public internet without using a proxy

```
setup_snat                 = true
```

These set of variables are specific for CSI Driver configuration and installation.

```
csi_driver_install         = false
csi_driver_type            = "stable"
csi_driver_version         = "v0.1.1"
```
**IMPORTANT**: This is an **experimental** feature and not yet ready for production.

These set of variables are specific for LUKS encryption configuration and installation.

```
luks_compliant              = false # Set it true if you prefer to use LUKS enable in ocp deployment
luks_config                 = [ { thumbprint = "", url = "" }, { thumbprint = "", url = "" }, { thumbprint = "", url = "" } ]
luks_filesystem_device      = "/dev/mapper/root"  #Set this value for file system device
luks_format                 = "xfs"  #Set value of format for filesystem
luks_wipe_filesystem        = true  #Set value of wipeFileSystem
luks_device                 = "/dev/disk/by-partlabel/root"  #Set value of luks device
luks_label                  = "luks-root"  #Set value of tang label
luks_options                = ["--cipher", "aes-cbc-essiv:sha256"]  #Set List of luks options for the luks encryption
luks_wipe_volume             = true  #Set value of wipeVolume
luks_name                   = "root"  #Set value of luks name
```
