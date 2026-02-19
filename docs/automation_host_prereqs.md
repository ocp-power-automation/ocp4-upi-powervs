
# Automation Host Prerequisites

- [Automation Host Prerequisites](#automation-host-prerequisites)
  - [Configure Your Firewall](#configure-your-firewall)
  - [Automation Host Setup](#automation-host-setup)
    - [Terraform](#terraform)
    - [PowerVS CLI](#powervs-cli)
    - [Git](#git)

## Configure Your Firewall
If your automation host is behind a firewall, you will need to ensure the following ports are open in order to use ssh, http, and https:
- 22, 443, 80

These additional ports are required for the ocp cli (`oc`) post-install:
- 6443

## Automation Host Setup

Install the following packages on the automation host. Select the appropriate install binaries based on your automation host platform - Mac/Linux/Windows.

### Terraform

**Terraform**: Please open the [link](https://www.terraform.io/downloads) for downloading the latest Terraform. For validating the version run `terraform version` command after install. Terraform version 1.2.0 and above is required.

Install Terraform and providers for Power environment:
1. Download and install the latest Terraform binary for Linux/ppc64le from https://github.com/ppc64le-development/terraform-ppc64le/releases.
2. Download the required Terraform providers for Power into your TF project directory. The following commands automatically fetch the latest release tag from GitHub, store it in an environment variable, and then download the matching archive:
```
$ cd <path_to_TF_project>
$ mkdir -p ./providers
$ export TERRAFORM_PROVIDERS_POWER_VERSION=$(curl -fsSL https://api.github.com/repos/ocp-power-automation/terraform-providers-power/releases/latest | grep '"tag_name"' | head -n1 | cut -d'"' -f4)
$ curl -fsSL https://github.com/ocp-power-automation/terraform-providers-power/releases/download/${TERRAFORM_PROVIDERS_POWER_VERSION}/archive.zip -o archive.zip
$ unzip -o ./archive.zip -d ./providers
$ rm -f ./archive.zip
```
3. Initialize Terraform at your TF project directory:
```
$ terraform init --plugin-dir ./providers
``` 

### PowerVS CLI

**PowerVS CLI**: Please download and install the CLI by referring to the following [instructions](https://cloud.ibm.com/docs/power-iaas-cli-plugin?topic=power-iaas-cli-plugin-power-iaas-cli-reference). Alternatively, you can use IBM Cloud [shell](https://cloud.ibm.com/shell) directly from the browser itself.

### Git

**Git**:  Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions on installing Git.
