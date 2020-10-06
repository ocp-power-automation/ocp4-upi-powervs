# PowerVS Prerequisites

- [PowerVS Prerequisites](#powervs-prerequisites)
  - [IBM Cloud Account](#ibm-cloud-account)
  - [Create Power Systems Virtual Server Service Instance](#create-power-systems-virtual-server-service-instance)
  - [Create Private Network](#create-private-network)
  - [Raise a Service Request to enable IP communication between PowerVS instances on private network](#raise-a-service-request-to-enable-ip-communication-between-powervs-instances-on-private-network)
  - [RHCOS and RHEL 8.2 Images for OpenShift](#rhcos-and-rhel-82-images-for-openshift)
    - [Creating OVA images](#creating-ova-images)
    - [Uploading to IBM Cloud Object Storage](#uploading-to-ibm-cloud-object-storage)
    - [Importing the images in PowerVS](#importing-the-images-in-powervs)


----------------------

## IBM Cloud Account
You'll need to have an IBM Cloud Account to be able to use Power Systems Virtual Server (PowerVS).

## Create Power Systems Virtual Server Service Instance

Login to [IBM Cloud Dashboard](https://cloud.ibm.com) and search for "**Power**" in the **Catalog**.
Select "**Power Systems Virtual Server**" and provide all the required inputs
to create the service instance.


![Search for Power](./media/image1.png)

![Select Power Systems Virtual Server](./media/image2.png)


![Fill Details](./media/image3.png)
1. Provide a meaningful name for your instance in the **Service name** field.
2. Select the proper **resource group**. More details on resource groups is available from the following [link](https://cloud.ibm.com/docs/account?topic=account-rgs)

![Provide service name](./media/image4.png)

![Create service](./media/image5.png)

## Create Private Network

A private network is required for your OCP cluster. Choose the previously created "**Service Instance**" and create a private subnet by selecting "**Subnets**" and providing the required inputs. If you see a screen displaying CRN and GUID, then click "View full details" to access the "Subnet" creation page.

You can create multiple OCP clusters in the same service instance using the same private network. If required you can also create multiple private networks.

Provide the required inputs for private subnet creation
![Select subnet](./media/image6.png)

![Provide Input](./media/image7.png)

![Create subnet](./media/image8.png)


## Raise a Service Request to enable IP communication between PowerVS instances on private network
In order for your instances to communicate within the subnet, you'll need to create a service request.

Click on **Support** in the top bar and scroll down to **Contact Support**, then select "**Create a case**"


![Create a case](./media/image9.png)

Select "**Power Systems Virtual Server**" tile

![Create a case Page](./media/image10.png)

Complete the details as shown using the following template:

- [Subject:] Enable communication between PowerVS instances on private network
- [Body:]
  ```
    Please enable IP communication between PowerVS instances for the following private network:
    Name: <your-subnet-name-from-above>
    Type: Private
    CIDR: <your ip subnet-from-above>
    VLAN ID: <your-vlan-id> (listed in your subnet details post-creation)
    Location: <your-location> (listed in your subnet details post-creation)
    Service Instance: <your-service-name>
  ```

![Sample support request ](./media/image11.png)

Click "**Continue**" to accept agreements, and then Click "**Submit case**".

![Submit Case](./media/image12.png)


## RHCOS and RHEL 8.2 Images for OpenShift
RHEL image is used for bastion and RHCOS is used for the OpenShift cluster nodes.

You'll need to create [OVA](https://en.wikipedia.org/wiki/Open_Virtualization_Format) formatted images for RHEL and RHCOS, upload them to IBM Cloud Object storage and then import these images as boot images in your PowerVS service instance.

Further, the image disk should be minimum of 120 GB in size.

### Creating OVA images

- If you have PowerVC then you can follow the instructions provided in the [link](https://www.ibm.com/support/knowledgecenter/en/SSXK2N_1.4.4/com.ibm.powervc.standard.help.doc/powervc_export_image_hmc.html) to export an existing PowerVC image to OVA image.
- Alternatively, you can use the following [guide](https://github.com/ocp-power-automation/infra/tree/master/scripts/images) to convert Qcow2 image to OVA, using a python script running on a Power LPAR.
  - RHEL 8.2 Qcow2 image is available from the following [link](https://access.redhat.com/downloads/content/279/ver=/rhel---8/8.2/ppc64le/product-software).

    Although the image is named KVM Guest Image, the same works for both KVM and PowerVM based systems.
  - RHCOS Qcow2 image is available from the following [link](https://mirror.openshift.com/pub/openshift-v4/ppc64le/dependencies/rhcos/4.5/4.5.4/rhcos-4.5.4-ppc64le-openstack.ppc64le.qcow2.gz).

    Ensure you use the file with `openstack` in its name.

### Uploading to IBM Cloud Object Storage

- **Create IBM Cloud Object Storage service and bucket** Please refer to the following [link](https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-getting-started-cloud-object-storage) for instructions to create IBM Cloud Object Storage service and required storage bucket to upload the OVA images.

  Ensure you create the bucket in either `us-east`, `us-south` or `eu-de` region. PowerVS currently supports import of images only from these regions. 

- **Create secret and access keys with Hash-based Message Authentication Code (HMAC)** Please refer to the following [link](https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-uhc-hmac-credentials-main) for instructions to create the keys required for importing the images into your PowerVS service instance.

- **Upload the OVA image to Cloud Object storage bucket** Please refer to the following [link](https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-upload) for uploading the OVA image to the respective bucket. Alternatively you can also use the following [python script](https://github.com/ocp-power-automation/infra/blob/master/scripts/images/upload_image.py).


### Importing the images in PowerVS
Choose the previously created PowerVS "**Service Instance**", click "**View full details**" and select "**Boot images**".
Click the "**Importing image**" option and fill the requisite details like image name, storage type and cloud object storage details.

Example screenshot showing import of RHEL image that is used for bastion
![Image Import-RHEL](./media/image-import1.png)

Example screenshot showing import of RHCOS image used for OCP
![Image Import-RHCOS](./media/image-import2.png)


Your PowerVS service instance is now ready for OpenShift clusters.
