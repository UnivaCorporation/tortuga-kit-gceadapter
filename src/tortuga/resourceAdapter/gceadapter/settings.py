# Copyright 2008-2018 Univa Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from tortuga.resourceAdapterConfiguration import settings


# Time (seconds) between attempts to update instance status to
# avoid thrashing
DEFAULT_SLEEP_TIME = 5

GROUP_INSTANCES = {
    'group': 'Instances',
    'group_order': 0
}
GROUP_AUTHENTICATION = {
    'group': 'Authentication',
    'group_order': 1
}
GROUP_DNS = {
    'group': 'DNS',
    'group_order': 2
}
GROUP_NETWORKING = {
    'group': 'Networking',
    'group_order': 3
}
GROUP_PREEMPTIBLE = {
    'group': 'Preemptible',
    'group_order': 4
}
GROUP_COST = {
    'group': 'Cost Sync',
    'group_order': 9
}

SETTINGS = {
    #
    # Instances
    #
    'project': settings.StringSetting(
        display_name='Project',
        required=True,
        description='Name of Google Compute Engine project',
        **GROUP_INSTANCES
    ),
    'zone': settings.StringSetting(
        display_name='Zone',
        required=True,
        description='Zone in which compute resources are created',
        **GROUP_INSTANCES
    ),
    'type': settings.StringSetting(
        display_name='Type',
        required=True,
        description='Virtual machine type; ror example, "n1-standard-1"',
        **GROUP_INSTANCES
    ),
    'image': settings.StringSetting(
        required=True,
        description='Name of image used when creating compute nodes',
        mutually_exclusive=['image_url', 'image_family'],
        overrides=['image_url', 'image_family'],
        **GROUP_INSTANCES
    ),
    'image_url': settings.StringSetting(
        required=True,
        description='URL of image used when creating compute nodes',
        mutually_exclusive=['image', 'image_family'],
        overrides=['image', 'image_family'],
        **GROUP_INSTANCES
    ),
    'image_family': settings.StringSetting(
        required=True,
        description='Family of image used when creating compute nodes',
        mutually_exclusive=['image', 'image_url'],
        overrides=['image', 'image_url'],
        **GROUP_INSTANCES
    ),
    'tags': settings.TagListSetting(
        display_name='Tags',
        description='A comma-separated list of tags in the form of '
                    'key=value',
        **GROUP_INSTANCES
    ),
    'startup_script_template': settings.FileSetting(
        display_name='Start-up Script Template',
        required=True,
        description='Filename of "bootstrap" script used by Tortuga to '
                    'bootstrap compute nodes',
        default='startup_script.py',
        base_path='/opt/tortuga/config/',
        **GROUP_INSTANCES
    ),
    'default_ssh_user': settings.StringSetting(
        display_name='Default SSH User',
        required=True,
        description='Username of default user on created VMs. "centos" '
                    'is an appropriate value for CentOS-based VMs.',
        **GROUP_INSTANCES
    ),
    'vcpus': settings.IntegerSetting(
        display_name='VCPUs',
        description='Number of virtual CPUs for specified virtual '
                    'machine type',
        **GROUP_INSTANCES
    ),
    'disksize': settings.IntegerSetting(
        display_name='Disk Size',
        description='Size of boot disk for virtual machine (in GB)',
        default='10',
        **GROUP_INSTANCES
    ),
    'accelerators': settings.StringSetting(
        display_name='Accelerators',
        description='List of accelerators to include in the instance '
                    'Format: "<accelerator-type>:<accelerator-count>,..."',
        **GROUP_INSTANCES
    ),
    'ssd': settings.BooleanSetting(
        display_name='SSD',
        description='Use SSD backed virtual machines',
        default='True',
        **GROUP_INSTANCES
    ),
    'randomize_hostname': settings.BooleanSetting(
        display_name='Randomize Hostname',
        description='Append random string to generated host names'
                    'to prevent name collisions in highly dynamic '
                    'environments',
        default='True',
        **GROUP_INSTANCES
    ),

    #
    # Authentication
    #
    'json_keyfile': settings.FileSetting(
        display_name='JSON Key File',
        description='Filename/path of service account credentials file'
                    'as provided by Google Compute Platform',
        base_path='/opt/tortuga/config/',
        **GROUP_AUTHENTICATION
    ),
    'default_scopes': settings.StringSetting(
        display_name='Default Scopes',
        required=True,
        list=True,
        list_separator='\n',
        default='https://www.googleapis.com/auth/devstorage.full_control\n'
                'https://www.googleapis.com/auth/compute',
        **GROUP_AUTHENTICATION
    ),

    #
    # DNS
    #
    'override_dns_domain': settings.BooleanSetting(
        display_name='Override DNS Domain',
        default='False',
        **GROUP_DNS
    ),
    'dns_domain': settings.StringSetting(
        display_name='DNS Domain',
        requires='override_dns_domain',
        **GROUP_DNS
    ),
    'dns_options': settings.StringSetting(
        display_name='DNS Options',
        **GROUP_DNS
    ),
    'dns_nameservers': settings.StringSetting(
        display_name='DNS Nameservers',
        default='',
        list=True,
        list_separator=' ',
        **GROUP_DNS
    ),

    #
    # Networking
    #
    'network': settings.StringSetting(
        display_name='Network',
        list=True,
        required=False,
        description='Network where virtual machines will be created',
        mutually_exclusive=['networks'],
        overrides=['networks'],
        **GROUP_NETWORKING
    ),
    'networks': settings.StringSetting(
        display_name='Networks',
        list=True,
        required=False,
        description='Networks associated with virtual machines',
        mutually_exclusive=['network'],
        overrides=['network'],
        **GROUP_NETWORKING
    ),

    #
    # Preemptible
    #
    'preemptible': settings.BooleanSetting(
        display_name='Preemptible',
        display='Launch instances as preemptible.',
        **GROUP_PREEMPTIBLE
    ),

    #
    # Settings for Navops Launch 2.0
    #
    'cost_sync_enabled': settings.BooleanSetting(
        display_name='Cost Synchronization Enabled',
        description='Enable GCE cost synchronization',
        requires=['cost_dataset_name'],
        **GROUP_COST
    ),
    'cost_dataset_name': settings.StringSetting(
        display_name='Dataset Name',
        requires=['cost_sync_enabled'],
        description='The name of the GCE BigQuery dataset in which '
                    'cost data is stored',
        **GROUP_COST,
    ),

    #
    # Unspecified
    #
    'sleeptime': settings.IntegerSetting(
        display_name="Sleep Time",
        advanced=True,
        default=str(DEFAULT_SLEEP_TIME)
    ),
    'createtimeout': settings.IntegerSetting(
        display_name="Create Timeout",
        advanced=True,
        default='600'
    ),
}
