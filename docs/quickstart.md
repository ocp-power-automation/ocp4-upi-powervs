# Installation Quickstart

- [Setup Repository](#setup-repository)
- [Setup Variables](#setup-variables)
- [Setup Data Files](#setup-data-files)
- [Start Install](#start-install)
- [Post Install](#post-install)
- [Cluster Access](#cluster-access)
- [Clean up](#clean-up)


## Setup Repository

Clone this git repository on the client machine:
```
$ git clone https://github.com/ocp-power-automation/ocp4-upi-powervs.git
$ cd ocp4-upi-powervs
```

**NOTE**: Please checkout a [release branch](https://github.com/ocp-power-automation/ocp4-upi-powervs/branches) eg. `release-4.5` for deploying a specific OCP release. The `master` branch will contain the latest changes which may not work with stable OCP releases but might work with pre-release OCP versions. You can also checkout stable [release tags](https://github.com/ocp-power-automation/ocp4-upi-powervs/releases) eg. `v4.5` for deploying a stable OCP releases.

To checkout specific release branch or tag please run:
```
$ git checkout <branch|tag name>
```

## Setup Variables.

Update the var.tfvars with values explained in the following sections. You can also set the variables using other ways mentioned [here](https://www.terraform.io/docs/configuration/variables.html#assigning-values-to-root-module-variables) such as -var option or environment variables.

### Setup IBM Cloud PowerVS Variables

Update the following variables specific to your environment.

 * `ibmcloud_api_key` : (Required) [IBM Cloud API key](https://cloud.ibm.com/iam/apikeys) associated with user's identity to authenticate with the IBM Cloud platform.
 * `ibmcloud_region` : (Required) The IBM Cloud region where you want to create the resources.
 * `ibmcloud_zone` : (Required) The zone of an IBM Cloud region where you want to create Power System resources. This value is required only when you want to work with a resource in a multizone-capable region.
 * `service_instance_id` : (Required) The cloud instance ID of your account. You can get the ID from instance name by using IBM Cloud CLI command: `ibmcloud resource service-instance <Name> | grep GUID`
 * `network_name` : (Required) The name of the network to be used for deploy operations.
 * `processor_type` : (Optional) The type of processor mode in which the VM will run (shared/dedicated).
 * `system_type` : (Optional) The type of system on which to create the VM (s922/e980).

### Setup Node Variables

Update the following variables specific to your cluster requirement.

 * `rhel_image_name` :  Name of the RHEL image that you want to use for bastion node.
 * `rhcos_image_name` : Name of the RHCOS image that you want to use for OCP nodes.
 * `bastion` : (Optional) Map of below parameters for bastion host.
    * `memory` : Memory in GBs required for bastion node. Minimum is 8GB (default).
    * `processors` : Number of vCPUs to use for bastion. Minimum is 1 vCPU (default).
 * `bootstrap` : (Optional) Map of below parameters for bootstrap host.
    * `memory` : Memory in GBs required for bootstrap node. Minimum is 16GB (default).
    * `processors` : Number of vCPUs to use for bootstrap node. Minimum is 2 vCPU (default).
    * `count` : Always set the value to 1 before starting the deployment. When the deployment is completed successfully set to 0 to delete the bootstrap node.
 * `master` : (Optional) Map of below parameters for master hosts.
    * `memory` : Memory in GBs required for master nodes. Minimum is 16GB (default).
    * `processors` : Number of vCPUs to use for master nodes. Minimum is 2 vCPU (default).
    * `count` : Number of master nodes. Minimum required is 3 (default).
 * `worker` : (Optional) Map of below parameters for worker hosts. (Atleaset 2 Workers are required for running router pods in HA mode)
    * `memory` : Memory in GBs required for worker nodes. Default is 16GB.
    * `processors` : Number of vCPUs to use for worker nodes. Default is 2 vCPU.
    * `count` : Number of worker nodes. Minimum required is 2 (default).

### Setup Additional Variables

Update the following variables specific to the nodes if required.

 * `rhel_username` : (Optional) The user that we should use for the connection to the bastion host. The default value is set as "root user.
 * `public_key_file` : (Optional) An OpenSSH-formatted public key file. Default path is 'data/id_rsa.pub'.
 * `private_key_file` : (Optional) Corresponding private key file. Default path is 'data/id_rsa'.
 * `private_key` : (Optional) The contents of an SSH key to use for the connection. Ignored if `public_key_file` is provided.
 * `public_key` : (Optional) The contents of corresponding key to use for the connection. Ignored if `public_key_file` is provided.
 * `rhel_subscription_username` : (Optional) The username required for RHEL subscription on bastion host. Leave empty if repos are already setup in the RHEL image(`rhel_image_name`) and subscription is not needed.
 * `rhel_subscription_password` : (Optional) The password required for RHEL subscription on bastion host.
 * `rhel_smt`: (Optional) The SMT value to set on the bastion node. Eg: on,off,2,4,8. Default is 4

### Setup OpenShift Variables

Update the following variables specific to OCP.

 * `openshift_install_tarball` : (Required) HTTP URL for OpenShift install tarball.
 * `openshift_client_tarball` : (Required) HTTP URL for OpenShift client (`oc`) tarball.
 * `cluster_domain` : (Required) Cluster domain name. `<cluster_id>.<cluster_domain>` forms the fully qualified domain name. Can also provide one of the online wildcard DNS domains: nip.io, xip.io & sslip.io.
 * `cluster_id_prefix` : (Required) Cluster identifier prefix. Should not be more than 8 characters. Nodes are pre-fixed with this value, please keep it unique.
 * `cluster_id` : (Optional) Cluster identifier, when not set random value will be used. Length cannot exceed 14 characters when combined with cluster_id_prefix.
 * `release_image_override` : (Optional) This is set to OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE while creating ignition files. Not applicable when using local registry setup.

### Setup Additional OpenShift Variables (Optional)

 * `installer_log_level` : (Optional) Log level for OpenShift install (e.g. "debug | info | warn | error") (default "info")
 * `ansible_extra_options` : (Optional) Ansible options to append to the ansible-playbook commands. Default is set to "-v".
 * `helpernode_repo` : (Optional) [ocp4-helpernode](https://github.com/RedHatOfficial/ocp4-helpernode) git repo URL.
 * `helpernode_tag` : (Optional) [ocp4-helpernode](https://github.com/RedHatOfficial/ocp4-helpernode) ansible playbook version to checkout.
 * `install_playbook_repo` : (Optional) [ocp4-playbooks](https://github.com/ocp-power-automation/ocp4-playbooks) git repo URL.
 * `install_playbook_tag` : (Optional) [ocp4-playbooks](https://github.com/ocp-power-automation/ocp4-playbooks) ansible playbooks version to checkout.
 * `pull_secret_file` : (Optional) Location of the OCP pull-secret file to be used. Default path is 'data/pull-secret.txt'.
 * `dns_forwarders` : (Optional) External DNS servers to forward DNS queries that cannot resolve locally. Eg: `"8.8.8.8; 9.9.9.9"`.
 * `rhcos_kernel_options` : (Optional) List of [kernel arguments](https://docs.openshift.com/container-platform/4.4/nodes/nodes/nodes-nodes-working.html#nodes-nodes-kernel-arguments_nodes-nodes-working) for the cluster nodes eg: ["slub_max_order=0","loglevel=7"]. Note that this will be applied after the cluster is installed, hence wait till all the nodes are in `Ready` status before you start using the cluster. Check nodes status using the command `oc get nodes`.
 * `chrony_config` : (Optional) Set to true to configure chrony (NTP) client on the CoreOS node. Default value is true.
 * `chrony_config_servers` : (Optional) List of NTP servers and options.
    * `server` : NTP server hostname or ip to sync with
    * `options`: chrony options to use for sync (ex: `iburst`)
 * `setup_squid_proxy` : (Optional) Flag to setup Squid proxy server on bastion node. Default value is true.
 * `proxy` : (Optional) Map of below parameters for using external proxy server to setup OCP on a private network. Set `setup_squid_proxy = false` when you want to use this.
    * `server` : Proxy server hostname or IP.
    * `port` : Proxy port to use (default is 3128).
    * `user` : Proxy server user for authentication.
    * `password` : Proxy server password for authentication.

### Setup Storage Variables (Optional)

Update the following variables specific to OCP storage. Note that currently only NFS storage provisioner is supported.

 * `storage_type` : (Optional) Storage provisioner to configure. Supported values: nfs (For now only nfs provisioner is supported, any other value won't setup a storageclass)
 * `volume_size` : (Optional) If storage_type is nfs, a volume will be created with given size (default 300) in GB and attached to bastion node. Eg: 1000 for 1TB disk.
 * `volume_type` : (Optional) The type of volume to create (ssd, standard, tier1, tier3).
 * `volume_shareable` : (Optional) If the volumes can be shared or not (true/false). Default is false.
 * `master_volume_size` : (Optional) Volume size in GB to attach to the master nodes. Not created by default.
 * `worker_volume_size` : (Optional) Volume size in GB to attach to the worker nodes. Not created by default.

### Setup Local Registry Variables (Optional)

Update the following variables specific to OCP local registry. Note that this is required only for restricted network install.

 * `enable_local_registry` : (Optional) Set to true to enable usage of local registry for restricted network install.
 * `local_registry_image` : (Optional) This is the name of the image used for creating local registry container.
 * `ocp_release_tag` : (Optional) The version of OpenShift you want to sync. Determine the tag by referring the [Repository Tags](https://quay.io/repository/openshift-release-dev/ocp-release?tab=tags) page.
 * `ocp_release_name` : (Optional) The type of release you want to sync. eg, ocp-release , ocp-release-nightly

### Setup OCP Upgrade Variables (Optional)

Update the following variables specific to OCP upgrade. The upgrade will be performed after a successful install of OCP.

 * `upgrade_image` : (Optional) OpenShift release image having higher and supported version. If set, OCP cluster will be upgraded to this image version. (e.g. `"quay.io/openshift-release-dev/ocp-release-nightly@sha256:552ed19a988fff336712a50..."`)
 * `upgrade_pause_time` : (Optional) Minutes to pause the playbook execution before starting to check the upgrade status once the upgrade command is executed.
 * `upgrade_delay_time` : (Optional) Seconds to wait before re-checking the upgrade status once the playbook execution resumes.


## Setup Data Files

You need to have the following files in data/ directory before running the Terraform templates.
```
$ ls data/
id_rsa  id_rsa.pub  pull-secret.txt
```
 * `id_rsa` & `id_rsa.pub` : The key pair used for accessing the hosts. These files are not required if you provide `public_key_file` and `private_key_file`.
 * `pull-secret.txt` : File containing keys required to pull images on the cluster. You can download it from RH portal after login https://cloud.redhat.com/openshift/install/pull-secret.


## Start Install

Run the following commands from within the cloned repository:

```
$ terraform init
$ terraform apply -var-file var.tfvars -parallelism=3
```

**NOTICE**: We have used [parallelism](https://www.terraform.io/docs/commands/apply.html#parallelism-n) to restrict parallel instance creation requests using the PowerVS client. This is due to a known issue where the apply fails at random parallel instance create requests. If you still get the error while creating the instance, you will have to delete the failed instance from PowerVS console and then run the apply command again.

Now wait for the installation to complete. It may take around 60 mins to complete provisioning.

**IMPORTANT**: When using NFS storage, the OpenShift image registry will be using NFS PV claim. Otherwise the image registry uses ephemeral PV.


## Post Install

### Delete Bootstrap Node

Once the deployment is completed successfully, you can safely delete the bootstrap node. This step is optional but recommended to free up the resources used during install.

1. Change the `count` value to 0 in `bootstrap` map variable and re-run the apply command. Eg: `bootstrap = {memory = "16", processors = "2", "count" = 0}`
2. Run command `terraform apply -var-file var.tfvars`


### Create API and Ingress DNS Records

Please skip this section if your `domain_name` is one of the online wildcard DNS domains: nip.io, xip.io & sslip.io.

Add the following records to your DNS server:
```
api.<cluster name>.<cluster domain>.  IN  A  <Bastion IP>
*.apps.<cluster name>.<cluster domain>.  IN  A  <Bastion IP>
```

If you're unable to create and publish these DNS records, you can add them to your `hosts` file. For Linux and Mac `hosts` file is located at /etc/hosts and for Windows it can be found at c:\Windows\System32\Drivers\etc\hosts.
```
<Bastion IP> api.<cluster name>.<cluster domain>
<Bastion IP> console-openshift-console.apps.<cluster name>.<cluster domain>
<Bastion IP> integrated-oauth-server-openshift-authentication.apps.<cluster name>.<cluster domain>
<Bastion IP> oauth-openshift.apps.<cluster name>.<cluster domain>
<Bastion IP> prometheus-k8s-openshift-monitoring.apps.<cluster name>.<cluster domain>
<Bastion IP> grafana-openshift-monitoring.apps.<cluster name>.<cluster domain>
<Bastion IP> <app name>.apps.<cluster name>.<cluster domain>
```

**Note**: For convenience, entries specific to your cluster will be printed at the end of a successful run. Just copy and paste value of output variable `etc_hosts_entries` to your hosts file.

**IMPORTANT**: OCP CLI console port 6443 is blocked by [default](https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-network-security#firewall-ports) over external IP. We are working on a resolution. Till then you can run the CLI commands from the bastion node. However, you can access the OCP web-console (port 443) remotely over external IP.


## Cluster Access

The OCP login credentials are in bastion host. To retrieve the same follow these steps:
1. `ssh -i data/id_rsa <rhel_username>@<bastion_ip>`
2. `cd ~/openstack-upi/auth`
3. `kubeconfig` can be used for CLI (`oc` or `kubectl`)
4. `kubeadmin` user and content of `kubeadmin-password` as password for GUI


The OpenShift web console URL will be printed with output variable `web_console_url` (eg. https://console-openshift-console.apps.test-ocp-090e.rhocp.com) on successful run. Open this URL on your browser and login with user `kubeadmin` and password as retrieved above.

The OpenShift command-line client is already configured on the bastion node with kubeconfig placed at `~/.kube/config`. Just start using the oc client directly.


## Clean up

To destroy after you are done using the cluster you can run command `terraform destroy -var-file var.tfvars` to make sure that all resources are properly cleaned up.
Do not manually clean up your environment unless both of the following are true:

1. You know what you are doing
2. Something went wrong with an automated deletion.
