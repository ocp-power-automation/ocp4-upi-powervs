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
   | lon             | lon0           |
   | tor             | tor01          |

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
bootstrap   = {memory      = "16",   processors  = "0.5",  "count"   = 1}
master      = {memory      = "16",   processors  = "0.5",  "count"   = 3}
worker      = {memory      = "32",   processors  = "0.5",  "count"   = 2}
```

`memory` is in `GBs` and `count` specifies the number of VMs that should be created for each type.

To enable high availability (HA) for the bastion node set the bastion `count` value to `2`.
Note that when HA is enabled, the automation will not setup NFS storage on bastion. Value `1` for bastion `count` implies the default non-HA bastion setup.

You can optionally set worker `count` value to `0` in which case all the cluster pods will be running on the master/supervisor nodes. 
Ensure that you use proper sizing for master/supervisor nodes to avoid resource starvation for containers.

For PowerVS, processors are equal to entitled physical count. So **N** processors == **N** physical core entitlements == **ceil[N]** vCPUs.
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
Change the image names according to your environment. Ensure that you use RHCOS 4.6.x image only with this automation code.
```
rhel_image_name     = "rhel-8.2"
rhcos_image_name    = "rhcos-4.6"
```
Note that the boot images should have a minimum disk size of 120GB

This variable specifies the name of the private network that is configured in your PowerVS service instance.
```
network_name        = "ocp-net"
```

These set of variables specify the type of processor and physical system type to be used for the VMs.
Change the default values according to your requirement.
```
processor_type      = "shared"  #Can be shared or dedicated
system_type         = "s922"    #Can be either s922 or e980
```

These set of variables specify the username and the SSH key to be used for accessing the bastion node.
```
rhel_username               = "root"
public_key_file             = "data/id_rsa.pub"
private_key_file            = "data/id_rsa"
```
Please note that only OpenSSH formatted keys are supported. Refer to the following links for instructions on creating SSH key based on your platform.
- Windows 10 - https://phoenixnap.com/kb/generate-ssh-key-windows-10
- Mac OSX - https://www.techrepublic.com/article/how-to-generate-ssh-keys-on-macos-mojave/
- Linux - https://www.siteground.com/kb/generate_ssh_key_in_linux/

Create the SSH key-pair and keep it under the `data` directory

These set of variables specify the RHEL subscription details.
This is sensitive data, and if you don't want to save it on disk, use environment variables `RHEL_SUBS_USERNAME` and `RHEL_SUBS_PASSWORD` and pass them to `terraform apply` command as shown in the [Quickstart guide](./quickstart.md#setup-terraform-variables).
If you are using CentOS as the bastion image, then leave these variables as-is.

```
rhel_subscription_username  = "user@test.com"
rhel_subscription_password  = "mypassword"
```

This variable specifies the number of hardware threads (SMT) that's used for the bastion node.
Default setting should be fine for majority of the use-cases.

```
rhel_smt                    = 4
```

### OpenShift Installation Details

These variables specify the URL for the OpenShift installer and client binaries.
Change the URL to the specific 4.6.x version that you want to install on PowerVS.
Reference link - `https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/`
```
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.6/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.6/openshift-client-linux.tar.gz"
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
```
Set the `cluster_domain` to `nip.io`, `xip.io` or `sslip.io` if you prefer using online wildcard domains.
Default is `ibm.com`.
The `cluster_id_prefix` should not be more than 8 characters. Nodes are pre-fixed with this value.
Default value is `test-ocp`

A random value will be used for `cluster_id` if not set.
The total length of `cluster_id_prefix`.`cluster_id` should not exceed 14 characters.

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
helpernode_repo            = "https://github.com/RedHatOfficial/ocp4-helpernode"
helpernode_tag             = "5eab3db53976bb16be582f2edc2de02f7510050d"
install_playbook_repo      = "https://github.com/ocp-power-automation/ocp4-playbooks"
install_playbook_tag       = "02a598faa332aa2c3d53e8edd0e840440ff74bd5"
```

These variables can be used when debugging ansible playbooks
```
installer_log_level         = "info"
ansible_extra_options       = "-v"
```

This variable specifies the external DNS servers to forward DNS queries that cannot be resolved locally.
```
dns_forwarders              = "1.1.1.1; 9.9.9.9"
```

List of [kernel arguments](https://docs.openshift.com/container-platform/4.4/nodes/nodes/nodes-nodes-working.html#nodes-nodes-kernel-arguments_nodes-nodes-working) for the cluster nodes.
Note that this will be applied after the cluster is installed and all the nodes are in `Ready` status.
```
rhcos_kernel_options        = []
```
- Example 1
  ```
  rhcos_kernel_options      = ["slub_max_order=0","loglevel=7"]
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
volume_type                 = "tier3"
volume_shareable            = false
```

If you need to attach additional data volumes to the OpenShift cluster nodes use the following variables.
```
master_volume_size          = "500"
worker_volume_size          = "500"
```

The following variables are specific to upgrading an existing installation.
```
upgrade_image = ""
upgrade_pause_time = "90"
upgrade_delay_time = "600"
```
