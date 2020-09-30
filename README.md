![GitHub release (latest release)](https://img.shields.io/github/v/release/ocp-power-automation/ocp4-upi-powervs?label=latest%20release)
[![License](https://img.shields.io/packagist/l/phplicengine/bitly)](LICENSE) [![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/ocp-power-automation/ocp4-upi-powervs/blob/master/CONTRIBUTING.md)

# Welcome

This repository contains Terraform templates, configurations and automation which leverages the [helpernode ansible playbook](https://github.com/RedHatOfficial/ocp4-helpernode) to assist in deploying [OpenShift Container Platform (OCP) 4.x](https://www.openshift.com/products/container-platform) on [IBM® Power Systems™ Virtual Server on IBM Cloud](https://www.ibm.com/cloud/power-virtual-server).

# Contributing

Take a look at [contributing](https://github.com/ocp-power-automation/ocp4-upi-powervs/blob/master/CONTRIBUTING.md) to learn how to help make this a better project.

:heavy_exclamation_mark: For any bugs, enhancement, requests, fixes, etc. [open a new GitHub issue](https://github.com/ocp-power-automation/ocp4-upi-powervs/issues/new) and ensure it is not duplicated.

:heavy_exclamation_mark: [Checkout the latest stable version](https://github.com/ocp-power-automation/ocp4-upi-powervs/tree/release-4.5).

:heavy_exclamation_mark: Ensure that you're working from the desired release-specific version of this `README` as you deploy by first selecting the appropriate branch from the drop-down above. At the time of this writing, the latest release is 4.5: [README](https://github.com/ocp-power-automation/ocp4-upi-powervs/tree/release-4.5). The `README` document located in the `master` branch changes frequently and should not be considered final.

# PowerVS Preparation

You first need to create and configure a PowerVS Service Intance in IBM Cloud before running this automation. You may follow this [guide](docs/ocp_prereqs_powervs.md) for instructions. To get started with PowerVS, [click here](https://cloud.ibm.com/docs/power-iaas?topic=power-iaas-getting-started). You can also learn more about PowerVS by watching some YouTube videos by clicking [here](https://www.youtube.com/watch?v=RywSfXT_LLs) and [here](https://www.youtube.com/playlist?list=PLVrJaTKVPbKM_9HU8fm4QsklgzLGUwFpv).

# Automation Host Preparation

You can run this automation from any system (laptop, virtual machine, etc.) with internet access. It has been tested on the following operating systems:

- Mac OSX (Darwin and Catalina)
- Linux (amd64/x86_64)
- Windows 10

Follow this [guide](docs/automation_host_prereqs.md) to complete the host preparation prerequisites.

# Installing OCP

Are you ready to get started? Follow the [quickstart](docs/quickstart.md) tutorial to install OpenShift Container Platform on PowerVS.
