# Installation Quickstart

- [Installation Quickstart](#installation-quickstart)
  - [Download the Automation Code](#download-the-automation-code)
  - [Setup Terraform Variables](#setup-terraform-variables)
  - [Start Install](#start-install)
  - [Post Install](#post-install)
      - [Delete Bootstrap Node](#delete-bootstrap-node)
      - [Create API and Ingress DNS Records](#create-api-and-ingress-dns-records)
  - [Cluster Access](#cluster-access)
    - [Using CLI](#using-cli)
    - [Using Web UI](#using-web-ui)
  - [Clean up](#clean-up)


## Download the Automation Code

You'll need to use git to clone the deployment code when working off the main branch

```
$ git clone https://github.com/ocp-power-automation/ocp4-upi-powervs.git
$ cd ocp4-upi-powervs
```

All further instructions assumes you are in the code directory eg. `ocp4-upi-powervs`

## Setup Terraform Variables

Update the [var.tfvars](../var.tfvars) based on your environment. Description of the variables are available in [var.tfvars-doc](./var.tfvars-doc.md).
You can use environment variables for sensitive data that should not be saved to disk.

```
$ set +o history
$ export IBMCLOUD_API_KEY=xxxxxxxxxxxxxxx
$ export RHEL_SUBS_USERNAME=xxxxxxxxxxxxxxx
$ export RHEL_SUBS_PASSWORD=xxxxxxxxxxxxxxx
$ set -o history
```

## Start Install

Run the following commands from within the directory.

```
$ terraform init
$ terraform apply -var-file var.tfvars -parallelism=3
```
If using template flavors for nodes configuration, then do the following.
```
$ terraform init
$ terraform apply -var-file var.tfvars -var-file compute-vars/<flavor-type>.tfvars
```

> Here, <flavor-type> is the node configuration template name. By default, `medium` flavor type is specified.

If using environment variables for sensitive data, then do the following, instead.
```
$ terraform init
$ terraform apply -var-file var.tfvars -parallelism=3 -var ibmcloud_api_key="$IBMCLOUD_API_KEY" -var rhel_subscription_username="$RHEL_SUBS_USERNAME" -var rhel_subscription_password="$RHEL_SUBS_PASSWORD"
```

> **Note**: We have used [parallelism](https://www.terraform.io/docs/commands/apply.html#parallelism-n) to restrict parallel instance creation requests using the PowerVS client. This is due to a known issue where the apply fails at random parallel instance create requests. If you still get the error while creating the instance, you will have to delete the failed instance from PowerVS console and then run the apply command again.

Now wait for the installation to complete. It may take around 60 mins to complete provisioning.

On successful install cluster details will be printed as shown below.
```
bastion_private_ip = 192.168.25.171
bastion_public_ip = 16.20.34.5
bastion_ssh_command = ssh -i data/id_rsa root@16.20.34.5
bootstrap_ip = 192.168.25.182
cluster_authentication_details = Cluster authentication details are available in 16.20.34.5 under ~/openstack-upi/auth
cluster_id = test-cluster-9a4f
etc_hosts_entries =
16.20.34.5 api.test-cluster-9a4f.mydomain.com console-openshift-console.apps.test-cluster-9a4f.mydomain.com integrated-oauth-server-openshift-authentication.apps.test-cluster-9a4f.mydomain.com oauth-openshift.apps.test-cluster-9a4f.mydomain.com prometheus-k8s-openshift-monitoring.apps.test-cluster-9a4f.mydomain.com grafana-openshift-monitoring.apps.test-cluster-9a4f.mydomain.com example.apps.test-cluster-9a4f.mydomain.com

install_status = COMPLETED
master_ips = [
  "192.168.25.147",
  "192.168.25.176",
]
oc_server_url = https://test-cluster-9a4f.mydomain.com:6443
storageclass_name = nfs-storage-provisioner
web_console_url = https://console-openshift-console.apps.test-cluster-9a4f.mydomain.com
worker_ips = [
  "192.168.25.220",
  "192.168.25.134",
]

```

When using wildcard domain like nip.io or xip.io then `etc_host_entries` is empty

```
bastion_private_ip = 192.168.25.171
bastion_public_ip = 16.20.34.5
bastion_ssh_command = ssh -i data/id_rsa root@16.20.34.5
bootstrap_ip = 192.168.25.182
cluster_authentication_details = Cluster authentication details are available in 16.20.34.5 under ~/openstack-upi/auth
cluster_id = test-cluster-9a4f
etc_hosts_entries =
install_status = COMPLETED
master_ips = [
  "192.168.25.147",
  "192.168.25.176",
]
oc_server_url = https://test-cluster-9a4f.16.20.34.5.nip.io:6443
storageclass_name = nfs-storage-provisioner
web_console_url = https://console-openshift-console.apps.test-cluster-9a4f.16.20.34.5.nip.io
worker_ips = [
  "192.168.25.220",
  "192.168.25.134",
]

```
These details can be retrieved anytime by running the following command from the root folder of the code
```
$ terraform output
```

In case of any errors, you'll have to re-apply. Please refer to [known issues](./known_issues.md) to get more details on potential issues and workarounds.

## Post Install


#### Delete Bootstrap Node

Once the deployment is completed successfully, you can safely delete the bootstrap node. This step is optional but recommended so as to free up the resources used.

1. Change the `count` value to 0 in `bootstrap` map variable and re-run the apply command. Eg: `bootstrap = {memory = "16", processors = "0.5", "count" = 0}`

2. Run command `terraform apply -var-file var.tfvars`


#### Create API and Ingress DNS Records

Please skip this section if your `cluster_domain` is one of the online wildcard DNS domains: nip.io, xip.io and sslip.io.

For all other domains, you can use one of the following options.

1. **Add entries to your DNS server**

    The general format is shown below:
    ```
    api.<cluster_id>.<cluster_domain>.  IN  A  <bastion_address>
    *.apps.<cluster_id>.<cluster_domain>.  IN  A  <bastion_address>
    ```
    You’ll need `dns_entries`. This is printed at the end of a successful install.
    Alternatively, you can retrieve it anytime by running `terraform output dns_entries` from the install directory.
    An example `dns_entries` output:
    ```
    api.test-cluster-9a4f.mydomain.com.  IN  A  16.20.34.5
    *.apps.test-cluster-9a4f.mydomain.com.  IN  A  16.20.34.5
    ```

2. **Add entries to your client system `hosts` file**

    For Linux and Mac `hosts` file is located at `/etc/hosts` and for Windows it's located at `c:\Windows\System32\Drivers\etc\hosts`.

    The general format is shown below:
    ```
    <bastion_address> api.<cluster_id>.<cluster_domain> console-openshift-console.apps.<cluster_id>.<cluster_domain> integrated-oauth-server-openshift-authentication.apps.<cluster_id>.<cluster_domain> oauth-openshift.apps.<cluster_id>.<cluster_domain> prometheus-k8s-openshift-monitoring.apps.<cluster_id>.<cluster_domain> grafana-openshift-monitoring.apps.<cluster_id>.<cluster_domain> <app name>.apps.<cluster_id>.<cluster_domain>
    ```

    You'll need `etc_host_entries`. This is printed at the end of a successful install.
    Alternatively you can retrieve it anytime by running `terraform output etc_hosts_entries` from the install directory.

    As an example, for the following `etc_hosts_entries`
    ```
    16.20.34.5 api.test-cluster-9a4f.mydomain.com console-openshift-console.apps.test-cluster-9a4f.mydomain.com integrated-oauth-server-openshift-authentication.apps.test-cluster-9a4f.mydomain.com oauth-openshift.apps.test-cluster-9a4f.mydomain.com prometheus-k8s-openshift-monitoring.apps.test-cluster-9a4f.mydomain.com grafana-openshift-monitoring.apps.test-cluster-9a4f.mydomain.com example.apps.test-cluster-9a4f.mydomain.com
    ```
    just add the following entry to the `hosts` file
    ```
    [existing entries in hosts file]

    16.20.34.5 api.test-cluster-9a4f.mydomain.com console-openshift-console.apps.test-cluster-9a4f.mydomain.com integrated-oauth-server-openshift-authentication.apps.test-cluster-9a4f.mydomain.com oauth-openshift.apps.test-cluster-9a4f.mydomain.com prometheus-k8s-openshift-monitoring.apps.test-cluster-9a4f.mydomain.com grafana-openshift-monitoring.apps.test-cluster-9a4f.mydomain.com example.apps.test-cluster-9a4f.mydomain.com
    ```

## Cluster Access

OpenShift login credentials are in the bastion host and the location will be printed at the end of a successful install.
Alternatively you can retrieve it anytime by running `terraform output` from the install directory.
```
[...]
bastion_public_ip = 16.20.34.5
bastion_ssh_command = ssh -i data/id_rsa root@16.20.34.5
cluster_authentication_details = Cluster authentication details are available in 16.20.34.5 under ~/openstack-upi/auth
[...]
```
There are two files under `~/openstack-upi/auth`
- **kubeconfig**: can be used for CLI access
- **kubeadmin-password**: Password for `kubeadmin` user which can be used for CLI, UI access

>**Note**: Ensure you securely store the OpenShift cluster access credentials. If desired delete the access details from the bastion node after securely storing the same.

You can copy the access details to your local system
```
$ scp -r -i data/id_rsa root@158.175.161.118:~/openstack-upi/auth/\* .
```

### Using CLI

OpenShift CLI `oc` can be downloaded from the following links. Use the one specific to your client system architecture.

For latest stable:

- [Mac OSX](https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable/openshift-client-mac.tar.gz)
- [Linux (x86_64)](https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable/openshift-client-linux.tar.gz)
- [Linux (ppc64le)](https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-client-linux.tar.gz)
- [Windows](https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable/openshift-client-windows.zip)

For pre-release:

- [Mac OSX](https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp-dev-preview/pre-release/openshift-client-mac.tar.gz)
- [Linux (x86_64)](https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp-dev-preview/pre-release/openshift-client-linux.tar.gz)
- [Linux (ppc64le)](https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/pre-release/openshift-client-linux.tar.gz)
- [Windows](https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp-dev-preview/pre-release/openshift-client-windows.zip)

Download the specific file, extract it and place the binary in a directory that is on your `PATH`
For more details check the following [link](https://docs.openshift.com/container-platform/latest/cli_reference/openshift_cli/getting-started-cli.html)

The CLI login URL `oc_server_url` will be printed at the end of successful install.
Alternatively you can retrieve it anytime by running `terraform output oc_server_url` from the install directory.
```
https://test-cluster-9a4f.mydomain.com:6443
```
In order to login the cluster you can use the `oc login <oc_server_url> -u kubeadmin -p <kubeadmin-password>`
Example:
```
$ oc login https://test-cluster-9a4f.mydomain.com:6443 -u kubeadmin -p $(cat kubeadmin-password)
```

You can also use the `kubeconfig` file
```
$ export KUBECONFIG=$(pwd)/kubeconfig
$ oc cluster-info
Kubernetes master is running at https://test-cluster-9a4f.mydomain.com:6443

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'

$ oc get nodes
NAME       STATUS   ROLES    AGE   VERSION
master-0   Ready    master   11h   v1.19.0+43983cd
master-1   Ready    master   11h   v1.19.0+43983cd
master-2   Ready    master   11h   v1.19.0+43983cd
worker-0   Ready    worker   11h   v1.19.0+43983cd
worker-1   Ready    worker   11h   v1.19.0+43983cd
```

>**Note:** The OpenShift command-line client `oc` is already configured on the bastion node with kubeconfig placed at `~/.kube/config`.

### Using Web UI

The web console URL will be printed at the end of a successful install.
Alternatively you can retrieve it anytime by running `terraform output web_console_url` from the install directory.
```
https://console-openshift-console.apps.test-cluster-9a4f.mydomain.com
```

Open this URL in your browser and login with user `kubeadmin` and password mentioned in the `kubeadmin-password` file.


## Clean up

To destroy after you are done using the cluster you can run command `terraform destroy -var-file var.tfvars -parallelism=3` to make sure that all resources are properly cleaned up.
Do not manually clean up your environment unless both of the following are true:

1. You know what you are doing
2. Something went wrong with an automated deletion.
