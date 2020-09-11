# **Table of Contents**

- [**Table of Contents**](#table-of-contents)
- [Introduction](#introduction)
- [Pre-requisites](#pre-requisites)
    - [Packages](#packages)
    - [Terraform Providers](#terraform-providers)
- [Image and LPAR requirements](#image-and-lpar-requirements)
- [OCP Install](#ocp-install)
- [Contributing](#contributing)


# Introduction
This repo contains Terraform templates to help with deployment of OpenShift Container Platform (OCP) 4.x on [IBM® Power Systems™ Virtual Server on IBM Cloud](https://www.ibm.com/cloud/power-virtual-server).

This project leverages the helpernode [ansible playbook](https://github.com/RedHatOfficial/ocp4-helpernode) internally for OCP deployment on IBM Power Systems Virtual Servers (PowerVS).

:heavy_exclamation_mark: *For bugs/enhancement requests etc. please open a GitHub issue*

# Pre-requisites

The automation needs to run from a system with internet access. This could be your laptop or a VM with public internet connectivity.
This automation code have been tested on the following Operating Systems:
 - Linux (x86_64)
 - Mac OSX (Darwin)
 - Windows

### Packages

Install the below required packages on the client machine.

- **Git**: Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions on installing the latest Git.
- **Terraform >= 0.13.0**: Please refer to the [link](https://learn.hashicorp.com/terraform/getting-started/install.html) for instructions on installing Terraform. For validating the version run `terraform version` command after install.

### Terraform Providers

At present Terraform registry does not support below plugins. Third-party providers can be manually installed using [local filesystem as a mirror](https://www.terraform.io/docs/commands/cli-config.html#filesystem_mirror). This is in addition to the provider plugins that are downloaded by Terraform during `terraform init`.

**Ignition provider v2.1.0**

1. Download the zip archive from [community-terraform-provider releases page](https://github.com/community-terraform-providers/terraform-provider-ignition/releases/tag/v2.1.0) .

2. Depending on your Operating System, create the Terraform plugins directory on your local filesystem if does not exist already.

> Linux: ~/.local/share/terraform/plugins OR /usr/local/share/terraform/plugins, OR /usr/share/terraform/plugins.

> Mac OSX: ~/Library/Application Support/io.terraform/plugins OR /Library/Application Support/io.terraform/plugins

> Windows: %APPDATA%/HashiCorp/Terraform/plugins

3. Under the path created in Step 2 please create the Igniton provider directory: `registry.terraform.io/terraform-providers/ignition/`
4. Place the downloaded zip file in Step 1 to `registry.terraform.io/terraform-providers/ignition/`

This is how the directory look for `linux_amd64`:
```
$ ls ~/.local/share/terraform/plugins/registry.terraform.io/terraform-providers/ignition/
terraform-provider-ignition_2.1.0_linux_amd64.zip
$
```

# Image and LPAR requirements

You'll need to create RedHat CoreOS (RHCOS) and RHEL 8.0 (or later) images in IBM Cloud Region.

Following are the recommended instance configs for OpenShift nodes that will be deployed with RHCOS image.
- Bootstrap, Master - 2 vCPUs, 16GB RAM, 120 GB Disk.

  PowerVS instances by default uses SMT=8. So with 2vCPUs, the number of logical CPUs as seen by the Operating System will be **16** (`2 vCPUs x 8 SMT`)

   **_This config is suitable for majority of the scenarios_**
- Worker - 2 vCPUs, 16GB RAM, 120 GB Disk

   **_Increase worker vCPUs, RAM and Disk based on application requirements_**

Following is the recommended instance config for the helper node that will be deployed with RHEL 8.0 (or later) image.
- Helper node (bastion) - 2vCPUs, 16GB RAM, 200 GB Disk
- Additional 300 GB Disk for NFS storage (This is the default)

# OCP Install

Follow the [quickstart](docs/quickstart.md) guide for OCP installation on PowerVS.

# Contributing
Please see the [contributing doc](https://github.com/ocp-power-automation/ocp4-upi-powervs/blob/master/CONTRIBUTING.md) for more details.
PRs are most welcome !!
