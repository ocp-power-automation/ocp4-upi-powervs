# Known Issues
This page lists the known issues and potential next steps when deploying OpenShift (OCP) in Power Systems Virtual Server (PowerVS)

## Terraform apply returns the following error
    
- **Error**:
  > timeout - last error: Error connecting to bastion: dial tcp 161.156.139.82:22: connect: operation timed out

- **Cause**: The public network attached to bastion is not reachable.

  Ping to the public/external IP of bastion node (eg. 161.156.139.82) will not return any response

- **Workaround**: Re-run TF again and if it doesn't help, destroy the TF resources and re-run.

  If it doesn't work, then please open a support case with IBM Cloud to fix issue with reachability of public IP for PowerVS instance.

## RHCOS instances in dashboard shows \"Warning\" Status

- **Cause**: This is due to RSCT daemon not being available for RHCOS

- **Workaround**: None

  You can ignore this. This will be fixed soon.

## Terraform apply fails with instance is not reachable error

- **Cause**: Sometimes the instances don't boot and and accessing the instance console from IBM Cloud dashboard shows  *grub rescue*

- **Workaround**: Rebooting the instance helps. If still facing the same issue, try destroying the TF resources and re-running the deployment

## Terraform apply fails with instance is not reachable error

- **Cause**:  Sometimes the instances don't boot and and accessing the instance console from IBM Cloud dashboard shows  *connect:   network is unreachable*

- **Cause**: Unknown

- **Workaround**: Rebooting the instance helps.

## Terraform provisioning fails with the following error

- **Error**:
  > Failed to get the instance Get https://eu-de.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/d239797b-7b2e-
  > 4790-a29d-439567556c83/pvm-instances/7d836f7d-8f21-4bef-9e10-ae6d8c2167a1: context deadline exceeded
  > on modules/4_nodes/nodes.tf line 92, in resource "ibm_pi_instance" "master":
  > 92: resource "ibm_pi_instance" "master" {

  Reapply will also fail
  > **module.nodes.ibm_pi_instance.master[0]: Creating...
  > Error: Failed to provision {"description":"bad request: invalid name server name already exists for cloud-     instance","error":"bad request"}
  > on modules/4_nodes/nodes.tf line 92, in resource "ibm_pi_instance" "master":
  > 92: resource "ibm_pi_instance" "master" {

- **Cause**: IBM Cloud API failed but resource got created and TF doesn't know that the resource got created.

- **Workaround**: Manually delete the resource from the dashboard and re-apply

## Terraform apply fails with these errors

- **Error**:
  - > module.install.null_resource.install (remote-exec): information. module.install.null_resource.install (remote-exec): changed: [192.168.25.12] => {"ansible_facts": {"discovered_interpreter_python": "/usr/libexec/platform-python"}, "changed": true, "cmd": "if lsmod|grep -q 'ibmveth'; then\n  sudo sysctl -w net.ipv4.route.min_pmtu=1450;\n  sudo sysctl -w net.ipv4.ip_no_pmtu_disc=1;\n  echo 'net.ipv4.route.min_pmtu = 1450' | sudo tee --append /etc/sysctl.d/88-sysctl.conf > /dev/null;\n  echo 'net.ipv4.ip_no_pmtu_disc = 1' | sudo tee --append /etc/sysctl.d/88-sysctl.conf > /dev/null;\nfi\n", "delta": "0:00:00.078644", "end": "2020-09-18 16:25:46.414601", "rc": 0, "start": "2020-09-18 16:25:46.335957", "stderr": "", "stderr_lines": [], "stdout": "net.ipv4.route.min_pmtu = 1450\nnet.ipv4.ip_no_pmtu_disc = 1", "stdout_lines": ["net.ipv4.route.min_pmtu = 1450", "net.ipv4.ip_no_pmtu_disc = 1"]}  
    > 
    > module.install.null_resource.install (remote-exec): NO MORE HOSTS LEFT *************************************************************  
    > 
    > module.install.null_resource.install (remote-exec): PLAY RECAP *********************************************************************   
    > module.install.null_resource.install (remote-exec): 192.168.25.105             : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.12              : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.121             : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.15              : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.235             : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.39              : ok=1    changed=0    unreachable=1    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.5               : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.82              : ok=28   changed=22   unreachable=0    failed=0    skipped=11   rescued=0    ignored=0

  - > module.install.null_resource.config (remote-exec): TASK [Downloading OCP4 Installer] **********************************************  
    > module.install.null_resource.config: Still creating... [1m40s elapsed]
    > module.install.null_resource.config (remote-exec): fatal: [localhost]: FAILED! => {"changed": false, "dest": "/usr/local/src/openshift-install-linux.tar.gz", "elapsed": 10, "msg": "Request failed: <urlopen error _ssl.c:880: The handshake operation timed out>", "url": "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/4.5.4/openshift-install-linux.tar.gz"}

  - > module.install.null_resource.install (remote-exec): fatal: [192.168.25.167]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: ssh: connect to host 192.168.25.167 port 22: Connection timed out", "unreachable": true}
    > 
    > module.install.null_resource.install (remote-exec): NO MORE HOSTS LEFT *************************************************************  
    > 
    > module.install.null_resource.install (remote-exec): PLAY RECAP *********************************************************************  
    > module.install.null_resource.install (remote-exec): 192.168.25.107             : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.165             : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.167             : ok=1    changed=0    unreachable=1    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.212             : ok=28   changed=22   unreachable=0    failed=0    skipped=11   rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.64              : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.76              : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.78              : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
    > module.install.null_resource.install (remote-exec): 192.168.25.81              : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0

- **Workaround**: Re-run the `terraform apply` command.
