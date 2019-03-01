# Google Compute Engine Resource Adapter Kit

February 2019 -- Version 1.1

## Overview

Google Compute Engine (GCE) support is enabled in Tortuga through the
installation and activation of the GCE resource adapter
kit.

The GCE resource adapter kit provides a resource adapter that can be
used to perform the following functions on the GCE platform:

* Add/delete node (virtual machine) instances
* Run a Tortuga installer node from within GCE
* Run a Tortuga installer node from outside GCE (also known
  as *hybrid* mode)

The GCE resource adapter maps each virtual machine to a
Tortuga compute node. It also enables *cloud bursting* when used in conjunction
with the Tortuga Simple Policy Engine.

## Installing the GCE resource adapter kit

Use `install-kit` to install the GCE resource adapter kit:

```shell
install-kit kit-gceadapter-7.0.3-0.tar.bz2
```

Once installed, the "management" component is enabled on the Tortuga installer
as follows:

```shell
enable-component -p gceadapter-7.0.3-0 management-7.0.3
/opt/puppetlabs/bin/puppet agent --verbose --onetime --no-daemonize
```

## Configuring a Service Account

A service account with the appropriate permissions is required to be
associated with the Tortuga installer. This section will describe the
process of doing that. For further reference, you can refer to the
Google documentation "[Manage APIs in the Cloud Platform Console](https://support.google.com/cloud/answer/6326510)".

### Create the Service Account

In the GCE console, click on the Navigation Menu -> IAM & Admin -> Service Accounts.
On that page, click on "Create Service Account". Fill out the service
account creation form as follows:

* **Name:** type in a name for the service account
* **Project role:** select the following roles:
  * Compute Image User
  * Compute Admin
* **Furnish a new private key:** check this box
  * **Key type:** JSON
* Click on *Save*

You will download a JSON key file as part of this process. Upload this
file to the Tortuga installer node. It is *recommended* to copy the service
account key file to `$TORTUGA_ROOT/config`. If not, it is necessary to
specify the full file path to the setting `json_keyfile`.

### Activate the service Account

On the installer:

```shell
gcloud auth activate-service-account --key-file=/path/to/your-key.json
```

## Configure the GCE Adapter

Configure the GCE resource adapter using the `adapter-mgmt`
command-line interface.

```shell
adapter-mgmt create --resource-adapter gce --profile Default \
    --setting default_ssh_user=centos \
    --setting image_url=<image_url> \
    --setting json_keyfile=<filename of json authentication file> \
    --setting network=default \
    --setting project=<project name> \
    --setting startup_script_template=startup_script.py \
    --setting type=n1-standard-1 \
    --setting zone=us-east1-b \
    --setting disksize=10
```

Refer to the section "Google Compute Engine resource adapter configuration
reference" below for further information.

**Note:** If you set the project, network, or zone to be different than
that of the Tortuga Installer, it WILL NOT WORK by default, as
additional networking setup will need to be done in GCE. The details of
these configuration changes are highly case-specific, and thus are not
covered in this document.

## GCE resource adapter configuration reference

| Setting                 | Description                                             |
|-------------------------|---------------------------------------------------------|
| zone                    | Zone in which compute resources are created. Zone names can be obtained from Console or using `gcloud compute regions list` |
| json_keyfile            | Filename/path of service account credentials file as provided by Google Compute Platform |
| type                    | Virtual machine type. For example, "n1-standard-1"      |
| network                 | Name of network where virtual machines will be created  |
| project                 | Name of Google Compute Engine project                   |
| startup_script_template | Filename of "bootstrap" script used by Tortuga to bootstrap compute nodes. The script `startup_script.py` is provided with the Google Compute Engine resource adapter kit and is compatible with RHEL/CentOS 6 and 7. It is automatically installed to `$TORTUGA_ROOT/config` during kit installation. |
| image                   | `[<project>/]<name>`. Name of VM image in (*optional*) project. Only one of `image`, `image_url`, or `image_family` is required. |
| image_url               | URL of Google Compute Engine image to be used when creating compute nodes. This URL can be obtained from the Google Compute Engine console or through the `gcloud` command-line interface <sup>\*</sup>  Only one of `image`, `image_url`, or `image_family` is required. |
| image_family            | `<project>/<family name>`. For example, to use the latest CentOS 7image, this value would be `centos-cloud/centos-7`.  Only one of `image`, `image_url`, or `image_family` is required. |
| default_ssh_user        | Username of default user on created VMs. 'centos' is an appropriate value for CentOS-based VMs. |
| tags                    | Keywords (separated by spaces) automatically added to all VMs launched by Tortuga. |
| vcpus                   | Number of virtual CPUs for specified virtual machine type. This setting overrides the lookup capability described below. |
| disksize                | (*optional*) Size of boot disk for virtual machine (in GB). Alternatively, use the disk settings from the software profile. See below for more details. |
| ssd                     | Set to "true" to enable SSD-backed virtual machines, set to "false" to use standard persistent disk. SSD-backed volumes are *enabled* by default. |

<sup>*</sup> Use the following `gcloud` command-line to determine the value for
`image_url` for CentOS 7:

```shell
gcloud compute images list --filter="name~\"centos-7.*\"" --uri
```

## Configuring compute node virtual disks

The GCE resource adapter can *optionally* use the disk configuration of the
software profile associated with GCE nodes. This allows specifying the boot disk
size as well as adding additional data disks to compute nodes at the time of
creation.

Alternatively, for single-disk compute nodes, only the `disksize` resource
adapter setting can be used.

### Setting boot disk size through software profile

When defining the compute node disk parameters through the software profile, it
is necessary to define a single `root` partition on the first device (denoted by
`--device 1.1`) and specify the disk size as follows:

```shell
update-software-profile --name Compute --add-partition root \
    --disk-size 10000 \
    --size 1 \
    --no-boot-loader \
    --file-system ext4 \
    --device 1.1 \
    --no-preserve
```

In this example, the disk size set to 10000 MB.

**Note:** Partitioning of persistent disks is currently **not** supported.
This can be done using Puppet or in the startup (bootstrap) script.

**Note**: the other settings (`size`, `no-boot-loader`, `file-system`, and
`no-preserve`) are ignored by the GCE resource adapter. They are required by
Tortuga only.

Refer to the *Tortuga Installation and Administration Guide* for addiitonal
information about software profile partitioning schema.

### Adding data disk(s)

To add additional data disks to a compute node, increment the first digit
in the argument to `--device` to indicate second, third, etc., volumes. For
example, to add a 100GB data disk to nodes in the "Compute" software
profile:

```shell
update-software-profile --name Compute --add-partition data \
    --disk-size 100000 \
    --size 1 \
    --no-boot-loader \
    --file-system ext4 \
    --device 2.1 \
    --no-preserve
```

## Creating GCE hardware profile

Create a default GCE-enabled hardware profile:

```shell
create-hardware-profile --name Compute
update-hardware-profile --name Compute \
    --resource-adapter gce --location remote --name-format compute-#NN
```

Map the newly created hardware profile to an existing software profile or
create new software profile as necessary.

Nodes can then be added using the `add-nodes` command-line interface.

Do not forget to map software and hardware profiles using
`set-profile-mapping`!

## GCE firewall rules

All nodes within the Tortuga-managed environment on GCE must
be unrestricted access to each other. This is the Google Compute Platform
default.

Port 22 (tcp) should be opened to allow connecting to GCE instances via `ssh`.

## GCE resource adapter usage

### Supported Node Operations

The GCE resource adapter supports the following Tortuga node
management commands:

* `add-nodes`
* `delete-node`
* `reboot-node`
* `shutdown-node`
* `startup-node`

### Adding Nodes

Nodes are added using the Tortuga `add-nodes` command. Specifying an Google
Compute Engine-enabled hardware profile (hardware profile with resource
adapter set to `gce`) automatically causes Tortuga to use the Google
Compute Engine resource adapter to manage the nodes.

For example, the following command-line will add 4 GCE nodes
to the software profile `execd` and hardware profile `execd`:

```shell
add-nodes --count 4 --software-profile Compute \
    --hardware-profile Compute
```

See Advanced Topics for additional information about enabling support for
creating preemptible virtual machines.

### Using SSH to access nodes

Connect to the Tortuga-managed compute nodes using `ssh USER@HOSTNAME`,
where `USER` is the `default_ssh_user` configured in the resource adapter
settings.

The GCE resource adapter uses the SSH key of the `root` user by default.

If `/root/.ssh/id_rsa` does not exist, use `ssh-keygen` to generate it
prior to adding nodes.

**Note:** If this key does not exist prior to launching compute nodes, the
compute nodes will not be accessible by SSH.

Use a custom Puppet module to configure other authorized SSH keys, as
necessary.

## Advanced Topics

### Disable randomized VM names

In the default configuration, the GCE resource adapter generates VM names
with random 5 character suffices. For example "compute-01-ahebx". This is
done to support highly dynamic environments where VMs are being added and
removed regularly to prevent compute node name clashes.

This setting can be disabled as follows:

```shell
adapter-mgmt update -r gce -p Default -s randomize_hostname=false
```

or re-enabled as follows:

```shell
adapter-mgmt update -r gce -p Default -s randomize_hostname=true
```

Alternatively, simply deleting the setting and falling back to default
behaviour:

```shell
adapter-mgmt update -r gce -p Default -d randomize_hostname
```

### Custom Machine Types

Google Compute Engine supports [custom machine types](https://cloud.google.com/custom-machine-types/) to allow you to create
compute VMs customized to your needs.

This is configured in Tortuga using a carefully formatted argument to the `type` setting.

For example, to create compute node VMs with 4 vcpus and 5GiB (5120MiB) RAM:

```shell
adapter-mgmt update -r gce -p Default -s type=custom-4-5120
```

### Instance type to VCPU mapping {#instance_mapping_gce}

The GCE platform does not provide the ability to
automatically query VM size metadata, so it is necessary to provide a
mapping mechanism.

This mapping is contained within the comma-separted value formatted file
`$TORTUGA_ROOT/config/gce-instance-sizes.csv` to allow Tortuga to
automatically set UGE exechost slots.

This file can be modified by the end-user. The file format is the GCE VM
size (ie. `n1-standard-1`) followed by a comma and the number of VCPUs for
that instance type. Some commonly used instance type to VCPUs mappings are
included in the default installation.

The default `gce-instance-sizes.csv` is as follows:

```shell
n1-standard-1,1
n1-standard-2,2
n1-standard-4,4
n1-standard-8,8
n1-standard-16,16
n1-standard-32,32
n1-standard-64,64
n1-standard-96,96
n1-highmem-2,2
n1-highmem-4,4
n1-highmem-8,8
n1-highmem-16,16
n1-highmem-32,32
n1-highmem-64,64
n1-highmem-96,96
n1-highcpu-2,2
n1-highcpu-4,4
n1-highcpu-8,8
n1-highcpu-16,16
n1-highcpu-32,32
n1-highcpu-64,64
n1-highcpu-96,96
```

### Support for preemptible virtual machines

The Google Compute Engine resource adapter supports [Preemptible Virtual Machines](https://cloud.google.com/preemptible-vms/)
through a standalone "helper" service in Tortuga called `gce_monitord`.

This service must be manually enabled and started after configuring the Google
Compute Engine resource adapter.

`gce_monitord` will poll GCE resources every 300s (default) monitoring
preemptible virtual machines that may have been terminted by Google Compute
Engine. These nodes will be automatically removed from Tortuga.

**Note:** `gce_monitord` will *only* monitor GCE VM
instances created/launched by Tortuga.

#### Enable support for preemptible virtual machines

1. Configure GCE resource adapter
2. Enable and start `gce_monitord`

    ```shell
    systemctl enable gce_monitord
    systemctl start gce_monitord

Output of `gce_monitord` service can be displayed through `journalctl`.

#### Adding preemptible nodes

Add nodes to Tortuga using the "--extra-arg preemptible" option.

```shell
add-nodes --software-profile execd --hardware-profile execd \
    --extra-arg preemptible --count 6
```

This command would add 6 preemptible nodes to the "execd" hardware profile and
"execd" software profile.

### Support for multiple network interfaces

Use the `networks` resource adapter configuration setting to define a
comma-separated list of networks to be configured in new Google Compute
Engine virtual machines provisioned by Tortuga.

Tortuga does **not** create or manage Google Cloud Platform VPC networks.
The following documentation assumes that one or more VPCs have been
previously configure and firewall rules allowing required ingress and
egress have been applied.

#### Configuration syntax

The following syntax is used to define a network for Google Compute
Engine VMs:

```shell
[<project>/]<network>:[<region>/]<subnet>[:flags]
```

If `<network>` and `<subnet`> are in the (current) `project` as defined in the
resource adapter settings, it is not necessary to specify the `<project>` and
`<region>`, respectively. For example, this syntax defines a network interface
on the network `mynetwork` and subnet `mysubnet` in the current project:

```shell
mynetwork:mysubnet
```

The "flags" argument is optional.

| Flag         |  Description                                               |
|--------------|------------------------------------------------------------|
| `external`   | allocate external (public) address                         |
| `noexternal` | do not allocate external (public) address                  |
| `primary`    | Denote network interface (and IP address) used by Tortuga |

Multiple flags must be separated by semicolons (";").

**Note:** because the semicolon is a command separator in most shells, it
is necessary to quote the setting in the `adapter-mgmt` command-line or
minimally, escape the semicolon.

For example:

```shell
adapter-mgmt ... -s networks="<network>:<subnet>:external;primary"
```

Following on the previous example, specifying `noexternal` will disable
external network access:

```shell
mynetwork:mysubnet:noexternal
```

#### External (Internet) network access

**Note:** If the `external` attribute is omitted from any network specified
by the `networks` setting, the first network interface is automatically
chosen to be assigned the external ip address.

#### Examples

##### Legacy networking

The legacy `network` setting remains unchanged:

```shell
adapter-mgmt update -r gce -p Default -s network=default
```

Since legacy mode networking enables external network access by default,
it is *redundant* to specify `network=default::external`.

When using a legacy VPC (only), use `network=default::noexternal` to
disable external access to VMs.

#### Two network interfaces

In this example, the VM is configured with two network interfaces.

The first network interface (`nic0`) is attached to the "`default`" VPC. In our
example, this VPC is in [legacy](https://cloud.google.com/vpc/docs/legacy)
mode and the subnet is automatically chosen by default. It is configured to
have a public (Internet accessible) ip address as indicated by the
`external` attribute.

The second network interface (`nic1`) is on the VPC named "`Tortuga-vpc2`"
specifically on the subnet "`subnet1`". The VPC `Tortuga-vpc2` exists in the
project configured for this resource adapter profile.

The network interfaces assigned to a Tortuga-provisioned VM can be
displayed under "VM instance details" in the Google Cloud Platform Console.

```shell
adapter-mgmt update -r gce -p Default \
    -s networks=default::external,Tortuga-vpc2:subnet1
```

Use the `primary` flag in the network interface specification to denote the
"primary" interface. That is the interface (and IP address) that should be
used by Tortuga. For example,

```shell
adapter-mgmt update -r gce -p Default \
    -s othernet:othernet-subnet1:external,Tortuga2:subnet1:external;primary
```

The second network interface is marked as the primary. The IP address of
this network interface will be used by Tortuga.

##### Referencing VPC from another project

The network interface is configured to use the VPC named `NETWORK1` in the
Google Cloud Platform project named `PROJECT2`. The subnetwork is configured
to be `SUBNET1` from the default region.

```shell
adapter-mgmt update -r gce -p Default \
    -s networks=PROJECT2/NETWORK1:SUBNET1
```

In the following example, the region for the subnet overrides the default
region for the resource adapter configuration profile:

```shell
adapter-mgmt update -r gce -p Default \
    -s networks=PROJECT2/NETWORK3:REGION4/SUBNET5
```

#### Troubleshooting

Pay particular attention to logs under `/var/log/celery/*`. Errors reported
by Google Compute Engine are logged verbatim by Tortuga.

**Note:** An error will be logged to `/var/log/tortugawsd` and the
`add-nodes` operation will be halted if both `network` and `networks`
settings are specified with `adapter-mgmt`.

### GCE VM image requirements

All custom virtual machine images must conform to the guidelines set by Google
Compute Platform. The "startup script" mechanism (enabled by default in
Google-provided images) is used by Tortuga to bootstrap compute instances. This
mechanism must be preserved for custom, non-Google provided images.

\newpage

[Google Compute Engine]: https://cloud.google.com/compute           "Google Compute Engine"
