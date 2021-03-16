
# Automation Host Prerequisites

- [Automation Host Prerequisites](#automation-host-prerequisites)
  - [Automation Host Setup](#automation-host-setup)
    - [Firewall Config](#configure-your-firewall)
    - [Terraform](#terraform)
    - [PowerVS CLI](#powervs-cli)
    - [Git [*OPTIONAL*]](#git-optional)

## Automation Host Setup

Install the following packages on the automation host. Select the appropriate install binaries based on your automation host platform - Mac/Linux/Windows.

### Configure Your Firewall
If your system is behind a firewall, you will need to ensure the following ports are open in order to use ssh, http, and https:
- 22, 443, 80

These additional ports are required for the ocp cli (`oc`) post-install:
- 6443

### Terraform

**Terraform >= 0.13.0**: Please refer to the [link](https://learn.hashicorp.com/terraform/getting-started/install.html) for instructions on installing Terraform. For validating the version run `terraform version` command after install.

Install Terraform and providers for Power environment:
1. Download the Terraform binary version 0.13.6 from https://www.power-devops.com/terraform and install it to /usr/local/bin.
2. Download the required Terraform providers for Power into your TF project directory:
```
$ cd <path_to_TF_project>
$ mkdir -p ./providers
$ curl -fsSL https://github.com/ocp-power-automation/terraform-providers-power/releases/download/v0.8/archive.zip -o archive.zip
$ unzip -o ./archive.zip -d ./providers
$ rm -f ./archive.zip
```
3. Initialize Terraform at your TF project directory:
```
$ terraform init --plugin-dir ./providers
``` 

### PowerVS CLI

**PowerVS CLI**: Please download and install the CLI by referring to the following [instructions](https://cloud.ibm.com/docs/power-iaas-cli-plugin?topic=power-iaas-cli-plugin-power-iaas-cli-reference). Alternatively, you can use IBM Cloud [shell](https://cloud.ibm.com/shell) directly from the browser itself.

### Git [*OPTIONAL*]

**Git**:  Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions on installing Git.
