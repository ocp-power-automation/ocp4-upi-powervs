# **Table of Contents**

- [**Table of Contents**](#table-of-contents)
- [Introduction](#introduction)
- [Pre-requisites](#pre-requisites)
- [Image and LPAR requirements](#image-and-lpar-requirements)
- [OCP Install](#ocp-install)
- [Contributing](#contributing)


# Introduction
This repo contains Terraform templates to help deployment of OpenShift Container Platform (OCP) 4.x using [IBM® Power Systems™ Virtual Server on IBM Cloud](https://www.ibm.com/cloud/power-virtual-server).

This project leverages the helpernode [ansible playbook](https://github.com/RedHatOfficial/ocp4-helpernode) internally for OCP deployment on IBM Power Systems Virtual Servers (PowerVS).

:heavy_exclamation_mark: *This automation is intended for test/development purposes only and there is no formal support. For bugs/enhancement requests etc. please open a GitHub issue*

# Pre-requisites

You need to identify a remote client machine for running the automation. This could be your laptop or a VM.

This code has been tested on the following x86-64 based Operating Systems:
 - Linux
 - MacOS (Darwin)
 - Windows

Install the below required packages on the client machine.

- **Git**: Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions
on installing the latest Git.
- **Terraform**: Please refer to the [link](https://learn.hashicorp.com/terraform/getting-started/install.html) for instructions on installing Terraform. You'll need to use version `0.12.20` or later. For validating the version run `terraform version` command after install.
- **IBM Cloud Provider plug-in**: Please refer to the section "Install the IBM Cloud Provider plug-in" from the [link](https://cloud.ibm.com/docs/terraform?topic=terraform-getting-started#install) for instructions on installing the provider plugin.


# Image and LPAR requirements

You'll need to create RedHat CoreOS (RHCOS) and RHEL 8.0 (or later) images in IBM Cloud Region.

Following are the recommended instance configs for OpenShift nodes that will be deployed with RHCOS image.
- Bootstrap, Master - 2 vCPUs, 16GB RAM, 120 GB Disk.

  PowerVS instances by default uses SMT=8. So with 2vCPUs, the number of logical CPUs as seen by the Operating System will be **16** (`2 vCPUs x 8 SMT`)

   **_This config is suitable for majority of the scenarios_**
- Worker - 2 vCPUs, 16GB RAM, 120 GB Disk

   **_Increase worker vCPUs, RAM and Disk based on application requirements_**

Following is the recommended instance config for the helper node that will be deployed with RHEL 8.0 (or later) image. If you want to create custom bastion instance via PowerVS UI and not via automation, Please refer to the [Create Power Systems Virtual Server Instance](docs/Create-Power-Systems-Virtual-Server-Instance.docx) guide for instructions.
- Helper node (bastion) - 2vCPUs, 16GB RAM, 200 GB Disk
- If NFS storage is requested, then additional 300 GB Disk is used

# OCP Install

Follow the [quickstart](docs/quickstart.md) guide to kickstart OCP installation using PowerVS.

# Contributing
Please see the [contributing doc](https://github.com/ocp-power-automation/ocp4-upi-powervs/blob/master/CONTRIBUTING.md) for more details.
PRs are most welcome !!
