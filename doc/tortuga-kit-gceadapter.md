# Google Compute Engine resource adapter

## Overview

Google Compute Engine support is enabled in Tortuga through the
installation and activation of the Google Compute Engine resource adapter
kit.

The Google Compute Engine resource adapter kit provides a resource adapter
that can be used to perform the following functions on the Google Compute
Engine platform:

* Add/delete node (virtual machine) instances
* Run a Tortuga installer node from within Google Compute Engine
* Run a Tortuga installer node from outside Google Compute Engine (also known
  as *hybrid* mode)

The Google Compute Engine resource adapter maps each virtual machine to a
Tortuga compute node. It also enables *cloud bursting* when used in conjunction
with the Tortuga Simple Policy Engine.

## Installing the Google Compute Engine resource adapter kit

Use `install-kit` to install the Google Compute Engine resource adapter kit:

```shell
install-kit kit-gceadapter-6.3.1-0.tar.bz2
```

Once installed, the "management" component is enabled on the Tortuga installer
as follows:

```shell
enable-component -p gceadapter-6.3.1-0 management-6.3
```

Using the Google Cloud Platform Console, create service account credentials
and download the service file to be used with the Tortuga Google Compute
Engine resource adapter. Refer to the Google documentation "[Manage APIs in
the Cloud Platform Console](https://support.google.com/cloud/answer/6326510)"
for information on setting up API keys.

It is *recommended* to copy the service account credentials file to
`$TORTUGA_ROOT/config`. If not, it is necessary to specify the
full file path to the setting `json_keyfile`.

Configure the Google Compute Engine resource adapter using the `adapter-mgmt`
command-line interface.

```shell
adapter-mgmt create --resource-adapter gce --profile default \
    --setting default_ssh_user=centos \
    --setting image_url=<image_url> \
    --setting json_keyfile=<filename of json authentication file> \
    --setting network=default \
    --setting project=<project name> \
    --setting startup_script_template=startup_script.py \
    --setting type=n1-standard-1 \
    --setting zone=us-east1-b \
    --setting disksize=10000
```

Refer to the section "Google Compute Engine resource adapter configuration
reference" below for further information.

## Google Compute Engine resource adapter configuration reference

| Setting                 | Description                                 |
|-------------------------|---------------------------------------------|
| zone                    | Zone in which compute resources are created. Zone names can be obtained from Console or using `gcloud compute regions list` |
| json_keyfile            | Filename/path of service account credentials file as provided by Google Compute Platform |
| type                    | Virtual machine type. For example, "n1-standard-1" |
| network                 | Name of network where virtual machines will be created |
| project                 | Name of Google Compute Engine project |
| vpn                     | Set to "true" to enable OpenVPN point-to-point VPN for hybrid installations (default is "false") |
| startup_script_template | Filename of "bootstrap" script used by Tortuga to bootstrap compute nodes |
| image_url               | URL of Google Compute Engine image to be used when creating compute nodes. This URL can be obtained from the Google Compute Engine console or through the `gcloud` command-line interface <sup>\*</sup> |
| default_ssh_user        | Username of default user on created VMs. 'centos' is an appropriate value for CentOS-based VMs. |
| tags                    | Keywords (separated by spaces) |
| vcpus                   | Number of virtual CPUs for specified virtual machine type |
| disksize                | Size of boot disk for virtual machine (in GB) |

<sup>*</sup> Use the following `gcloud` command-line to determine the value for
`image_url` for CentOS 7:

```shell
gcloud compute images describe \
    $(gcloud compute images list \
    --filter="name~\"centos-7.*\"" --format='value(name)') \
    --project centos-cloud --format='value(selfLink)'
```

## Creating Google Compute Engine hardware profile

Create a default Google Compute Engine-enabled hardware profile:

```shell
create-hardware-profile --name execd
update-hardware-profile --name execd \
    --resource-adapter gce --location remote
```

Map the newly created hardware profile to an existing software profile or
create new software profile as necessary.

Nodes can then be added using the `add-nodes` command-line interface.

## Google Compute Engine firewall rules

All nodes within the Tortuga-managed environment on Google Compute Engine must
be unrestricted access to each other. This is the Google Compute Platform
default.

Port 22 (tcp) should be opened to allow connecting to GCE instances via `ssh`.

## Google Compute Engine resource adapter usage

### Supported Node Operations

The Google Compute Engine resource adapter supports the following Tortuga node
management commands:

* `activate-node`
* `add-nodes`
* `delete-node`
* `idle-node`
* `reboot-node`
* `transfer-node`
* `shutdown-node`
* `startup-node`

### Adding Nodes

Nodes are added using the Tortuga `add-nodes` command. Specifying an Google
Compute Engine-enabled hardware profile (hardware profile with resource
adapter set to `gce`) automatically causes Tortuga to use the Google
Compute Engine resource adapter to manage the nodes.

For example, the following command-line will add 4 Google Compute Engine nodes
to the software profile `execd` and hardware profile `execd`:

```shell
add-nodes --count 4 --software-profile execd \
    --hardware-profile execd
```

See Advanced Topics for additional information about enabling support for
creating preemptible virtual machines.

## Advanced Topics

### Configuring virtual machine persistent disks

Persistent disks, including the boot disk, may be configured through the existing software profile partitioning schema mechanism (`update-software-profile ... --add-partition ...`).

Optionally, using the `disksize` setting in the resource adapter configuration allows a default disk size for the boot disk without configuring the software profile partitions. For most users with simple (single disk) virtual machine configurations, using the `disksize` resource adapter configuration setting is sufficient. The following example is for more advanced configurations.

To configure a boot disk using software profile partitions:

```shell
update-software-profile --name compute \
    --add-partition root \
    --disk-size 10000 \
    --device 1.1 \
    --file-system ext4 \
    --size 1 \
    --no-preserve \
    --no-boot-loader
```

This example assumes the software profile "compute" already exists  without a partitioning scheme. While all of the above settings are required, the key valyes are `--device`, `--disk-size`.

To add a second persistent disk (PD), increase the value of the parameter to `--device`. For example, `--device 2.1` represents the second device, first partition.

**Note:** Partitioning of persistent disks is currently **not** supported. This can be done using Puppet or in the startup (bootstrap) script.

Refer to the Tortuga Installation and Administration Guide for addiitonal information about software profile partitioning schema.

### Instance type to VCPU mapping {#instance_mapping_gce}

The Google Compute Engine platform does not provide the ability to
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

### Enabling support for preemptible virtual machines

Tortuga supports Google Compute Engine
[preemptible virtual machines](https://cloud.google.com/preemptible-vms/)
through a standalone "helper" daemon in Tortuga called `gce_monitord`.
This daemon must be enabled/started after configuring the Google Compute
Engine resource adapter.

`gce_monitord` will poll Google Compute Engine resources every 60s monitoring
preemptible virtual machines that may have been terminted by Google Compute
Engine. These nodes will be automatically removed from the Tortuga-managed
cluster.

**Note:** `gce_monitord` will *only* monitor Google Compute Engine VM
instances created/launched by Tortuga.

Enable support for preemptible virtual machines:

1. Configure Google Compute Engine resource adapter
1. Enable and start `gce_monitord`

    RHEL/CentOS 7

        systemctl enable gce_monitord
        systemctl start gce_monitord

    RHEL/CentOS 6

        chkconfig gce_monitord on
        service gce_monitord start

Once preemptible support has been enabled, add nodes to Tortuga using the
"--extra-arg preemptible" option. For example:

    add-nodes --software-profile execd --hardware-profile execd \
        --extra-arg preemptible --count 6

This command would add 6 preemptible nodes to the "execd" hardware profile and
"execd" software profile.

### Google Compute Engine VM image requirements

All custom virtual machine images must conform to the guidelines set by Google
Compute Platform. The "startup script" mechanism (enabled by default in
Google-provided images) is used by Tortuga to bootstrap compute instances. This
mechanism must be preserved for custom, non-Google provided images.

\newpage

[Google Compute Engine]: https://cloud.google.com/compute           "Google Compute Engine"
