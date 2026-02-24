# Building Terraform on ppc64le

This guide provides instructions on how to install Go and build Terraform from source on a Linux ppc64le environment.

## Prerequisites

Building Terraform from source requires the Go programming language to be installed on your system.

### Install Go

1. Download the latest Go binary for Linux ppc64le from the [official Go downloads page](https://go.dev/dl/).
2. Follow the [official Go installation instructions](https://go.dev/doc/install) to install it on your system.
3. Verify the installation by running:
   ```bash
   go version
   ```

## Build Terraform

Once Go is installed, follow these steps to build the latest version of Terraform:

1. Clone the Terraform repository:
   ```bash
   cd ..
   git clone https://github.com/hashicorp/terraform.git
   cd terraform
   ```

2. Fetch the latest release tag and check out that version:
   ```bash
   TAG=$(curl -s https://api.github.com/repos/hashicorp/terraform/releases/latest | grep tag_name | cut -d '"' -f4)
   git checkout tags/$TAG
   ```

3. Build and install Terraform for Linux/ppc64le:
   ```bash
   env GOOS=linux GOARCH=ppc64le go install .
   ```

## Update PATH

After the build completes, the `terraform` binary will be located in your Go bin directory (typically `~/go/bin`). Add this directory to your `PATH` to make the `terraform` command available globally:

```bash
export PATH="$HOME/go/bin:$PATH"
```

To make this change permanent, add the above line to your shell profile (e.g., `~/.bashrc` or `~/.zshrc`).

Verify the installation:
```bash
terraform version
```
