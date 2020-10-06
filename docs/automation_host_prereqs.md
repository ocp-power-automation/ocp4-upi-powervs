# Automation Host Prerequisites
- [Automation Host Prerequisites](#automation-host-prerequisites)
  - [Automation Host Setup](#automation-host-setup)
    - [Terraform](#terraform)
    - [IBM Cloud Terraform Provider](#ibm-cloud-terraform-provider)
    - [PowerVS CLI](#powervs-cli)
    - [Git [*OPTIONAL*]](#git-optional)

## Automation Host Setup

Install the following packages on the automation host. Select the appropriate install binaries based on your automation host platform - Mac/Linux/Windows

### Terraform

**Terraform 0.12.29**:

1. Download Terraform 0.12.29 release binary for your Operating System from the following [link](https://releases.hashicorp.com/terraform/0.12.29/)
2. Extract the package and move it to a directory included in your system's `PATH` .
3. Run `terraform version` command after install to validate that you are using `0.12.29` version.


### IBM Cloud Terraform Provider

**IBM Cloud Terraform Provider v1.9.0**:

1. Download v1.9.0 release binary for your Operating System from the following [link](https://github.com/IBM-Cloud/terraform-provider-ibm/releases/tag/v1.9.0)

2. Extract the package to retrieve the binary file

3. Create a hidden directory for the plugin
    ```
    $ mkdir $HOME/.terraform.d/plugins
    ```
4. Move the IBM Cloud Terraform Provider files to the previously created hidden directory.
    ```
    $ mv $HOME/Downloads/terraform-provider-ibm* $HOME/.terraform.d/plugins/
    ```
5. Navigate to the hidden directory and verify that the installation is complete.
    ```
    $ cd $HOME/.terraform.d/plugins && ./terraform-provider-ibm_*
    ```
    Example output:
    ```
    2020/10/05 23:30:33 IBM Cloud Provider version 1.9.0
    This binary is a plugin. These are not meant to be executed directly.
    Please execute the program that consumes these plugins, which will
    load any plugins automatically
    ```

No additional configuration required for the IBM Cloud Terraform Provider.

### PowerVS CLI

**PowerVS CLI**: Please download and install the CLI by referring to the following [instructions](https://cloud.ibm.com/docs/power-iaas-cli-plugin?topic=power-iaas-cli-plugin-power-iaas-cli-reference). Alternatively, you can use IBM Cloud [shell](https://cloud.ibm.com/shell) directly from the browser itself.

### Git [*OPTIONAL*]

**Git**: Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions on installing Git.
