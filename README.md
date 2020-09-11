# **Table of Contents**

- [**Table of Contents**](#table-of-contents)
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Image and LPAR requirements](#image-and-lpar-requirements)
- [OCP Install](#ocp-install)
- [Known Issues](#known-issues)
- [Contributing](#contributing)


# Introduction
This repo contains Terraform templates to help deployment of OpenShift Container Platform (OCP) 4.x on [IBM® Power Systems™ Virtual Server on IBM Cloud](https://www.ibm.com/cloud/power-virtual-server).

This project leverages the helpernode [ansible playbook](https://github.com/RedHatOfficial/ocp4-helpernode) internally for OCP deployment on IBM Power Systems Virtual Servers (PowerVS).

:heavy_exclamation_mark: *For bugs/enhancement requests etc. please open a GitHub issue*

# Prerequisites

The automation needs to run from a system with internet access. This could be your laptop or a VM with public internet connectivity. This automation code have been tested on the following Operating Systems:
 - Linux (x86_64)
 - Mac OSX (Darwin)
 - Windows

Install the following required packages on the system.

- **Git**: Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions on installing the latest Git.
- **Terraform >= 0.12.2, < 0.13**: Please refer to the [link](https://learn.hashicorp.com/terraform/getting-started/install.html) for instructions on installing Terraform. For validating the version run `terraform version` command after install.
- **IBM Cloud Terraform Provider v1.9.0**: Please refer to the section "Install the IBM Cloud Provider plug-in" from the [link](https://cloud.ibm.com/docs/terraform?topic=terraform-getting-started#install) for instructions on installing the provider plugin.
You could also install the provider locally by running the command `go get -u github.com/IBM-Cloud/terraform-provider-ibm` and moving the binary from `$GOPATH/bin/` to [plugins directory](https://www.terraform.io/docs/configuration/providers.html#third-party-plugins).
- **PowerVS CLI**: Please download and install the CLI by referring to the following [instructions](https://cloud.ibm.com/docs/power-iaas-cli-plugin?topic=power-iaas-cli-plugin-power-iaas-cli-reference)

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

# Known Issues
Please check the following [doc](docs/known_issues.md) for list of known issues.

# Contributing
Please see the [contributing doc](https://github.com/ocp-power-automation/ocp4-upi-powervs/blob/master/CONTRIBUTING.md) for more details.
PRs are most welcome !!
