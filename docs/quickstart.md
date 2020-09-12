# Installation Quickstart

- [Installation Quickstart](#installation-quickstart)
  - [Download the Automation Code](#download-the-automation-code)
  - [Setup Terraform Variables](#setup-terraform-variables)
  - [Start Install](#start-install)
  - [Post Install](#post-install)
    - [Delete Bootstrap Node](#delete-bootstrap-node)
    - [Create API and Ingress DNS Records](#create-api-and-ingress-dns-records)
  - [Cluster Access](#cluster-access)
  - [Clean up](#clean-up)


## Download the Automation Code

Head to the [release](https://github.com/ocp-power-automation/ocp4-upi-powervs/releases
) page and download the latest stable release.
Extract the release bundle on your system.

You can also use `curl` or `wget` to download the stable release code as shown below.
```
$ curl -L https://github.com/ocp-power-automation/ocp4-upi-powervs/archive/v4.5.zip -o v4.5.zip
$ unzip v4.5.zip
$ cd ocp4-upi-powervs-4.5
```

You can also clone git repository on your system.
Ensure you checkout the release branch when using git.
```
$ git clone https://github.com/ocp-power-automation/ocp4-upi-powervs.git -b release-4.5 ocp4-upi-powervs-4.5
$ cd ocp4-upi-powervs-4.5
```

All further instructions assumes you are in the code directory eg. `ocp4-upi-powervs-4.5`

## Setup Terraform Variables

Update the [var.tfvars](../var.tfvars) based on your environment. Description of the variables are available in the following [link](./var.tfvars-doc.md)


## Start Install

Run the following commands from within the directory.

```
$ terraform init
$ terraform apply -var-file var.tfvars -parallelism=3
```

**NOTICE**: We have used [parallelism](https://www.terraform.io/docs/commands/apply.html#parallelism-n) to restrict parallel instance creation requests using the PowerVS client. This is due to a known issue where the apply fails at random parallel instance create requests. If you still get the error while creating the instance, you will have to delete the failed instance from PowerVS console and then run the apply command again.

Now wait for the installation to complete. It may take around 60 mins to complete provisioning.

On successful install cluster details will be printed as shown below.
```
bastion_private_ip = 192.168.25.171
bastion_public_ip = 16.20.34.5
bastion_ssh_command = ssh root@16.20.34.5
bootstrap_ip = 192.168.25.182
cluster_authentication_details = Cluster authentication details are available in 16.20.34.5 under ~/openstack-upi/auth
cluster_id = test-cluster
etc_hosts_entries =
install_status = COMPLETED
master_ips = [
  "192.168.25.147",
  "192.168.25.176",
  "192.168.25.168",
]
oc_server_url = https://test-cluster-9a4f.16.20.34.5.nip.io:6443
storageclass_name = nfs-storage-provisioner
web_console_url = https://console-openshift-console.apps.test-cluster-9a4f.16.20.34.5.nip.io
worker_ips = [
  "192.168.25.220",
  "192.168.25.134",
  "192.168.25.145",
]
```
These details can be retrieved anytime by running the following command from the root folder of the code
```
$ terraform output
```

In case of any errors, you'll have to re-apply. Please refer to [known issues](./known_issues.md) to get more details on potential issues and workarounds.

## Post Install


### Delete Bootstrap Node

Once the deployment is completed successfully, you can safely delete the bootstrap node. This step is optional but recommended so as to free up the resources used.

1. Change the `count` value to 0 in `bootstrap` map variable and re-run the apply command. Eg: `bootstrap = {memory = "16", processors = "0.5", "count" = 0}`
2. Run command `terraform apply -var-file var.tfvars`


### Create API and Ingress DNS Records

Please skip this section if your `cluster_domain` is one of the online wildcard DNS domains: nip.io, xip.io and sslip.io.

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


## Cluster Access

The OCP login credentials are in bastion host. To retrieve the same follow these steps:
1. `ssh -i data/id_rsa <rhel_username>@<bastion_ip>`
2. `cd ~/openstack-upi/auth`
3. `kubeconfig` can be used for CLI (`oc` or `kubectl`)
4. `kubeadmin` user and content of `kubeadmin-password` as password for GUI or CLI access


The OpenShift web console URL will be printed with output variable `web_console_url` (eg. https://console-openshift-console.apps.test-ocp-090e.rhocp.com) on successful run. Open this URL on your browser and login with user `kubeadmin` and password as retrieved above.

The OpenShift command-line client is already configured on the bastion node with kubeconfig placed at `~/.kube/config`. Just start using the `oc` client directly.


## Clean up

To destroy after you are done using the cluster you can run command `terraform destroy -var-file var.tfvars` to make sure that all resources are properly cleaned up.
Do not manually clean up your environment unless both of the following are true:

1. You know what you are doing
2. Something went wrong with an automated deletion.
