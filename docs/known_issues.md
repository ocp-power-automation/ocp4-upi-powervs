# Known Issues
This page lists the known issues and potential next steps when deploying OpenShift (OCP) in Power Systems Virtual Server (PowerVS)

-  **Terraform apply returns the following error**

    > **"Error: timeout - last error: Error connecting to bastion: dial tcp
    > 161.156.139.82:22: connect: operation timed out"**
    >
    > **Cause:** The public network attached to bastion is not reachable.
    >
    > Ping to the public/external IP of bastion node (eg. 161.156.139.82)
    > will not return any response
    >
    > **Workaround**: Re-run TF again and if it doesn't help, destroy the TF resources and re-run.
    >
    > If it doesn't work, then please open a support case with IBM Cloud to fix issue with reachability of public IP for PowerVS instance.

-  **RHCOS instances in dashboard shows \"Warning\" Status**

    > **Cause**: This is due to RSCT daemon not being available for RHCOS
    >
    > **Workaround**: None
    >
    > You can ignore this. This will be fixed soon.

-  **Terraform apply fails with instance is not reachable error**

    > **Cause**: Sometimes the instances don't boot and and accessing the instance console from IBM Cloud dashboard shows  *grub rescue*
    >
    > **Workaround**: Rebooting the instance helps. If still facing the same
    > issue, try destroying the TF resources and re-running the deployment
    >

- **Terraform apply fails with instance is not reachable error**

    > **Cause**:  Sometimes the instances don't boot and and accessing the instance console from IBM Cloud dashboard shows  *connect:   network is unreachable*
    >
    > **Cause**: Unknown
    >
    > **Workaround**: Rebooting the instance helps.
    >


- **Terraform provisioning fails with the following error**

    > **Error: Failed to get the instance Get https://eu-de.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/d239797b-7b2e-     > 4790-a29d-439567556c83/pvm-instances/7d836f7d-8f21-4bef-9e10-ae6d8c2167a1: context deadline exceeded
    > on modules/4_nodes/nodes.tf line 92, in resource "ibm_pi_instance" "master":
    > 92: resource "ibm_pi_instance" "master" {**
    >
    >**Reapply will also fail**
    >
    >**module.nodes.ibm_pi_instance.master[0]: Creating...
    >Error: Failed to provision {"description":"bad request: invalid name server name already exists for cloud-     instance","error":"bad request"}
    >on modules/4_nodes/nodes.tf line 92, in resource "ibm_pi_instance" "master":
    >92: resource "ibm_pi_instance" "master" {

    > **Cause**: IBM Cloud API failed but resource got created and TF doesn't know that the resource got created.
    >
    > **Workaround**: Manually delete the resource from the dashboard and re-apply
    >

- **Terraform destroy fails with the following error**

    > **Error: {"description":"an error has occurred; please try again: unable to delete subnet for network 30dab9c3-  0e4b->     > 41b0-94b2-d865769b8056 for cloud instance b88bf8fc4d3349ffa4d1497e24996b1f: Expected HTTP response code [] when  accessing [DELETE https://192.168.4.136:9696/v2.0/subnets/7776ef27-bb9f-4358-a5d3-564f33a3201f], but got 409  instead\n{\"NeutronError\": {\"message\": \"Unable to complete operation on subnet 7776ef27-bb9f-4358-a5d3-564f33a3201f: One  or more ports have an IP allocation from this subnet.\", \"type\": \"SubnetInUse\", \"detail\": \"\"}}","error":"internal  server error"}**
    >
    > **Cause**: A previous failed apply resulting in inconsistency where the instance is created but TF is unaware of the same
    >
    > **Workaround**: Delete the instance and the associated network from the dashboard and re-run destroy

- **Accessing IBM Container Registry fails with the following error**

    > **TLS handshake timeout**
    >
    > **Cause**: This is due to the MTU settings of the underlying GRE tunnel used for public internet access.
    >
    > **Workaround**: Set MTU of the public interface in bastion to 1450.
    >
    > Let's say env3 is the public interface then set MTU to 1450 by running the following command
    > `ifconfig env3 mtu 1450`
