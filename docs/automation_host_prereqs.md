
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

**Terraform >= 0.13.0**: Please refer to the [link](https://learn.hashicorp.com/terraform/getting-started/install.html) for instructions on installing Terraform. For validating the version run `terraform version` command after install.

### PowerVS CLI

**PowerVS CLI**: Please download and install the CLI by referring to the following [instructions](https://cloud.ibm.com/docs/power-iaas-cli-plugin?topic=power-iaas-cli-plugin-power-iaas-cli-reference). Alternatively, you can use IBM Cloud [shell](https://cloud.ibm.com/shell) directly from the browser itself.

### Git

**Git**:  Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions on installing Git.
