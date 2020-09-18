
# **Table of Contents**

- [**Table of Contents**](#table-of-contents)
- [Automation Host Setup](#automation-host-setup)
  - [Terraform Providers](#terraform-providers)

# Automation Host Setup

Install the following packages on the automation host. Select the appropriate installable based on your automation host platform - Mac/Linux/Windows

- **Terraform >= 0.13.0**: Please refer to the [link](https://learn.hashicorp.com/terraform/getting-started/install.html) for instructions on installing Terraform. For validating the version run `terraform version` command after install.

- **IBM Cloud Terraform Provider v1.9.0**: Please refer to the section "Install the IBM Cloud Provider plug-in" from the [link](https://cloud.ibm.com/docs/terraform?topic=terraform-getting-started#install) for instructions on installing the provider plugin.

- **PowerVS CLI**: Please download and install the CLI by referring to the following [instructions](https://cloud.ibm.com/docs/power-iaas-cli-plugin?topic=power-iaas-cli-plugin-power-iaas-cli-reference).

- **Git**: [*OPTIONAL*] Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions on installing Git.

## Terraform Providers

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