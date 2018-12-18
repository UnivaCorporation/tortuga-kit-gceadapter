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

# pylint: disable=no-member

import json
import os.path
import random
import re
import shlex
import subprocess
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import apiclient
import gevent
import googleapiclient.discovery
from gevent.queue import JoinableQueue
from google.auth import compute_engine
from google.oauth2 import service_account
from sqlalchemy.orm.session import Session
from tortuga.db.models.hardwareProfile import HardwareProfile
from tortuga.db.models.instanceMapping import InstanceMapping
from tortuga.db.models.instanceMetadata import InstanceMetadata
from tortuga.db.models.nic import Nic
from tortuga.db.models.node import Node
from tortuga.db.models.softwareProfile import SoftwareProfile
from tortuga.db.nodesDbHandler import NodesDbHandler
from tortuga.exceptions.commandFailed import CommandFailed
from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.exceptions.nodeNotFound import NodeNotFound
from tortuga.exceptions.unsupportedOperation import UnsupportedOperation
from tortuga.node import state
from tortuga.resourceAdapter.resourceAdapter import ResourceAdapter
from tortuga.resourceAdapter.utility import get_provisioning_hwprofilenetwork
from tortuga.resourceAdapterConfiguration import settings
from tortuga.utility.cloudinit import get_cloud_init_path


API_VERSION = 'v1'

GCE_URL = 'https://www.googleapis.com/compute/%s/projects/' % (API_VERSION)

EXTERNAL_NETWORK_ACCESS_CONFIG = [
    {
        'type': 'ONE_TO_ONE_NAT',
        'name': 'External NAT',
    },
]


def get_instance_name_from_host_name(hostname):
    return hostname.split('.', 1)[0]


def get_disk_volume_name(instance_name, diskNumber):
    """Return persistent volume name based on instance name and disk number
    """

    return '%s-disk-%02d' % (instance_name, diskNumber)


class Gce(ResourceAdapter): \
        # pylint: disable=too-many-public-methods

    __adaptername__ = 'gce'

    # Time (seconds) between attempts to update instance status to
    # avoid thrashing
    DEFAULT_SLEEP_TIME = 5

    settings = {
        'zone': settings.StringSetting(
            required=True,
            description='Zone in which compute resources are created'
        ),
        'json_keyfile': settings.FileSetting(
            required=True,
            description='ilename/path of service account credentials file as '
                        'provided by Google Compute Platform',
            base_path='/opt/tortuga/config/'
        ),
        'type': settings.StringSetting(
            required=True,
            description='Virtual machine type; ror example, "n1-standard-1"'
        ),
        'network': settings.StringSetting(
            list=True,
            description='Network where virtual machines will be created',
            mutually_exclusive=['networks'],
            overrides=['networks'],
        ),
        'networks': settings.StringSetting(
            list=True,
            description='List of networks where virtual machines will be created',
            mutually_exclusive=['network'],
            overrides=['network'],
        ),
        'project': settings.StringSetting(
            required=True,
            description='Name of Google Compute Engine project'
        ),
        'image': settings.StringSetting(
            required=True,
            description='Name of image used when creating compute nodes',
            mutually_exclusive=['image_url', 'image_family'],
            overrides=['image_url', 'image_family'],
        ),
        'image_url': settings.StringSetting(
            required=True,
            description='URL of image used when creating compute nodes',
            mutually_exclusive=['image', 'image_family'],
            overrides=['image', 'image_family'],
        ),
        'image_family': settings.StringSetting(
            required=True,
            description='Family of image used when creating compute nodes',
            mutually_exclusive=['image', 'image_url'],
            overrides=['image', 'image_url'],
        ),
        'startup_script_template': settings.FileSetting(
            required=True,
            description='Filename of "bootstrap" script used by Tortuga to '
                        'bootstrap compute nodes',
            default='startup_script.py',
            base_path='/opt/tortuga/config/'
        ),
        'default_ssh_user': settings.StringSetting(
            required=True,
            description='Username of default user on created VMs. "centos" '
                        'is an appropriate value for CentOS-based VMs.'
        ),
        'tags': settings.StringSetting(
            description='Keywords (separated by spaces)'
        ),
        'vcpus': settings.IntegerSetting(
            description='Number of virtual CPUs for specified virtual '
                        'machine type'
        ),
        'disksize': settings.IntegerSetting(
            description='Size of boot disk for virtual machine (in GB)',
            default='10'
        ),
        'metadata': settings.StringSetting(
            advanced=True
        ),
        'sleeptime': settings.IntegerSetting(
            advanced=True,
            default=str(DEFAULT_SLEEP_TIME)
        ),
        'default_scopes': settings.StringSetting(
            required=True,
            list=True,
            list_separator='\n',
            default='https://www.googleapis.com/auth/devstorage.full_control\n'
                    'https://www.googleapis.com/auth/compute',
        ),
        'override_dns_domain': settings.BooleanSetting(default='False'),
        'dns_domain': settings.StringSetting(requires='override_dns_domain'),
        'dns_search': settings.StringSetting(),
        'dns_options': settings.StringSetting(),
        'dns_nameservers': settings.StringSetting(
            default='',
            list=True,
            list_separator=' '
        ),
        'createtimeout': settings.IntegerSetting(
            advanced=True,
            default='600'
        ),
        'ssd': settings.BooleanSetting(
            description='Use SSD backed virtual machines',
            default='True',
        ),
    }

    def __init__(self, addHostSession: Optional[str] = None):
        super(Gce, self).__init__(addHostSession=addHostSession)

        self.__session_map_lock = threading.Lock()
        self.__session_map = {}
        self.__session_lock = threading.Lock()

        self.__running_on_gce = None

    @property
    def is_running_on_gce(self):
        if self.__running_on_gce is None:
            self.__running_on_gce = is_running_on_gce()

        return self.__running_on_gce

    def __get_session(self, profile_name: str):
        """Return Google Compute session"""

        # Check 'session_map' for existing session
        self.__session_map_lock.acquire()

        if profile_name in self.__session_map:
            self.getLogger().debug(
                'Found session for profile [%s]' % (profile_name))

            session = self.__session_map[profile_name]
        else:
            self.getLogger().debug(
                'Initializing session for profile [%s]' % (
                    profile_name))

            session = self.__init_session(profile_name)

            self.__session_map[profile_name] = session

        self.__session_lock.acquire()

        self.__session_map_lock.release()

        return session

    def __release_session(self):
        self.getLogger().debug('Unlocking session lock')

        self.__session_lock.release()

    def __validate_configuration(self, session, dbHardwareProfile,
                                 dbSoftwareProfile): \
            # pylint: disable=unused-argument
        """
        Raises:
            InvalidArgument
        """

    def start(self, addNodesRequest: dict, dbSession: Session,
              dbHardwareProfile: HardwareProfile,
              dbSoftwareProfile: Optional[SoftwareProfile] = None) \
        -> List[Node]: \
            # pylint: disable=unused-argument
        """
        :raises: HardwareProfileNotFound
        :raises: SoftwareProfileNotFound
        :raises: InvalidArgument
        """

        session = self.__get_session(
            addNodesRequest.get('resource_adapter_configuration')
        )

        try:
            if dbSoftwareProfile is None or dbSoftwareProfile.isIdle:
                # Add idle nodes
                nodes = self.__addIdleNodes(
                    session, dbSession, addNodesRequest, dbHardwareProfile,
                    dbSoftwareProfile)
            else:
                # Add regular instance-backed (active) nodes
                nodes = self.__addActiveNodes(
                    session, dbSession, addNodesRequest,
                    dbHardwareProfile, dbSoftwareProfile)

            # This is a necessary evil for the time being, until there's
            # a proper context manager implemented.
            self.addHostApi.clear_session_nodes(nodes)

            return nodes
        finally:
            self.__release_session()

    def validate_start_arguments(self, addNodesRequest, dbHardwareProfile,
                                 dbSoftwareProfile):
        """
        Validate arguments to start() API

        addNodesRequest['resource_adapter_configuration'] is updated with
        the cfg name that is actually used. If not initially provided,
        'default' is always the default.

        :raises UnsupportedOperation: Attempt to start (add) idle node(s)
        """

        super().validate_start_arguments(
            addNodesRequest, dbHardwareProfile, dbSoftwareProfile
        )

        cfgname = addNodesRequest['resource_adapter_configuration']

        session = self.__get_session(cfgname)

        self.__validate_configuration(
            session, dbHardwareProfile, dbSoftwareProfile)

        if not dbSoftwareProfile or dbSoftwareProfile.isIdle:
            raise UnsupportedOperation(
                'Idle nodes not supported with GCE resource adapter')

    def suspendActiveNode(self, node: Node) -> bool:
        self.getLogger().debug(
            'suspendActiveNode(node=[{}]): not supported'.format(node.name))

        # Suspend is not currently supported for cloud-based instances
        return False

    def idleActiveNode(self, nodes: List[Node]) -> str:
        # FYI... when this method is called, 'Node' are already marked idle

        # Iterate over list of 'Node' database objects.
        for node in nodes:
            session = self.__get_session(
                node.instance.resource_adapter_configuration.name
            )

            try:
                self.__deleteInstance(session, node)

                # Update instance cache
                if node.instance:
                    node.instance = None

                node.nics[0].ip = None
            finally:
                self.__release_session()

        # This is a carryover from past behaviour. The resource adapter
        # should be responsible for setting the nodes' state.
        return 'Discovered'

    def activateIdleNode(self, node, softwareProfileName,
                         softwareProfileChanged):
        """
        Raises:
            CommandFailed
        """

        self.getLogger().debug(
            'activateIdleNode(): node=[%s], softwareProfileName=[%s],'
            ' softwareProfileChanged=[%s]' % (
                node.name, softwareProfileName, softwareProfileChanged))

        session = self.__get_session(
            node.instance.resource_adapter_configuration.name
        )

        try:
            configDict = session['config']

            # Sanity checking... ensure node is actually idle
            if node.instance:
                # According to the instance cache, this node is reported to
                # be running.

                raise CommandFailed(
                    'Compute Engine instance [%s] is already running' % (
                        node.name))

            instance_name = get_instance_name_from_host_name(node.name)

            metadata = self.__get_metadata(session)

            if 'startup_script_template' in session['config']:
                startup_script = self.__getStartupScript(
                    session['config'])

                if startup_script:
                    metadata.append(('startup-script', startup_script))

                # Uncomment this to create local copy of startup script
                # tmpfn = '/tmp/startup_script.py.%s' % (dbNode.name)
                # with open(tmpfn, 'w') as fp:
                #     fp.write(startup_script + '\n')
            else:
                self.getLogger().warning(
                    'Startup script template not specified.'
                    ' Compute Engine instance  [%s] will be started'
                    ' without startup script' % (instance_name))

            # Create any persistent disks before launching instance
            response = self.__create_persistent_disk(
                session, instance_name, 10)

            result = _blocking_call(
                session['connection'].svc,
                configDict['project'], response,
                polling_interval=session['config']['sleeptime'])

            self.getLogger.debug(
                'persistent disk creation result=[%s]' % (result))

            selfLink = result['targetLink']

            response = self.__launch_instance(
                session, instance_name, metadata, persistent_disks=selfLink)

            result = _blocking_call(
                session['connection'].svc,
                configDict['project'], response,
                polling_interval=session['config']['sleeptime'])

            if 'error' in result:
                # Error attempting to activate idle node
                self.__process_error_response(instance_name, result)

            # Instance was launched successfully
            node.instance = InstanceMapping(
                instance=instance_name,
                instance_metadata=[
                    InstanceMetadata(
                        key='zone', value=response['zone'].split('/')[-1],
                    )
                ]
            )

            bTimedOut = False

            timeoutTime = int(time.time()) + configDict['createtimeout']

            while not bTimedOut and not self.isAborted():
                time.sleep(configDict['sleeptime'])

                instance = self.__getInstance(session, instance_name)

                if instance is None:
                    # Instance no longer exists (???)
                    raise CommandFailed(
                        'Unable to get Compute Engine instance %s.'
                        ' Check /var/log/tortuga for details' % (
                            instance_name))

                status = instance['status']

                if status == 'RUNNING':
                    previous_state = node.state
                    node.state = state.NODE_STATE_PROVISIONED
                    self.fire_state_change_event(
                        db_node=node, previous_state=previous_state)
                    break

                if int(time.time()) > timeoutTime:
                    bTimedOut = True

            if bTimedOut or self.isAborted():
                # TODO: terminate instance

                self.getLogger().error(
                    'Timed out while attempting to activate'
                    ' node [%s]' % (node.name))

                self.nodeManager.idleNode(node.name)

                return

            # Get IP address from instance
            node.nics[0].ip = self.__get_instance_internal_ip(instance)

            # TODO

            self.getLogger().debug(
                'activateIdleNode(): node [%s] activated'
                ' successfully' % (node.name))
        finally:
            self.__release_session()

    def deleteNode(self, nodes: List[Node]) -> None:
        """
        Raises:
            CommandFailed
        """

        # Iterate over list of Node database objects
        for node in nodes:
            self.getLogger().debug('deleteNode(): node=[%s]', node.name)

            if not node.instance or \
                    not node.instance.resource_adapter_configuration:
                # this node does not have an associated VM
                self.getLogger().debug(
                    'Node [%s] does not have an associated VM',
                    node.name
                )
                continue

            gce_session = self.__get_session(
                node.instance.resource_adapter_configuration.name)

            try:
                self.__deleteInstance(gce_session, node)

                self.__node_cleanup(node)

                # Update SAN API
                self.__process_deleted_disk_changes(node)
            finally:
                self.__release_session()

    def __get_project_and_zone_metadata(self, node: Node) -> Tuple[str, str]:
        project = None
        zone = None

        # iterate over instance metadata
        for md in node.instance.instance_metadata:
            if md.key == 'project':
                project = md.value
            elif md.key == 'zone':
                zone = md.value

        return project, zone

    def __process_deleted_disk_changes(self, node):
        """Remove persistent disks from SAN API 'catalog'.

        Note: this does *NOT* remove the persistent disk from Google Compute
        Engine
        """

        # Get disk changes for node being deleted
        diskChanges = self.sanApi.discoverStorageChanges(node, True)

        for removedDiskNumber, disk in \
            [(int(disk_index), diskChanges['removed'][disk_index])
             for disk_index in diskChanges['removed'].keys()]:
            storageAdapter = disk['adapter']

            if storageAdapter != 'default':
                # Ignore requests for non-default storage adapter
                continue

            volume_name = get_disk_volume_name(
                get_instance_name_from_host_name(node.name),
                removedDiskNumber)

            self.getLogger().debug(
                'Removing persistent disk [%s]' % (volume_name))

            self.sanApi.deleteDrive(node, removedDiskNumber)

    def __node_cleanup(self, node: Node):
        self.getLogger().debug(
            '__node_cleanup(): node=[%s]' % (node.name))

        self.addHostApi.clear_session_node(node)

        if node.isIdle:
            # Idle node

            return

        # Update SAN API
        self.__process_deleted_disk_changes(node)

    def transferNode(self, nodeIdSoftwareProfileTuples,
                     newSoftwareProfileName):
        for node, oldSoftwareProfileName in nodeIdSoftwareProfileTuples:
            self.getLogger().debug(
                'transferNode (node=[%s]): old software profile: %s,'
                ' software profile in node: %s, '
                ' new software profile: %s' % (
                    node.name, oldSoftwareProfileName,
                    node.softwareprofile.name
                    if node.softwareprofile else None,
                    newSoftwareProfileName))

            # simply idle and activate
            self.idleActiveNode([node])

            self.activateIdleNode(
                node,
                newSoftwareProfileName,
                (newSoftwareProfileName != oldSoftwareProfileName))

    def startupNode(self, nodes: List[Node],
                    remainingNodeList: Optional[str] = None,
                    tmpBootMethod: Optional[str] = 'n'): \
            # pylint: disable=unused-argument
        """TODO: not implemented"""

    def __validate_default_scopes(self, default_scopes):
        """
        Raises:
            ConfigurationError
        """

        # Iterate over specified 'default_scopes' and ensure they are
        # properly formatted URLs.
        for url in default_scopes:
            urlResult = urllib.parse.urlparse(url)

            if not urlResult.scheme.lower() in ['http', 'https']:
                self.getLogger().error(
                    'Invalid URL specified in default_scopes:'
                    ' \"%s\" must be a properly formatted URL' % (url))

                raise ConfigurationError(
                    'Invalid URL [%s] specified in default_scopes' % (url))

    def process_config(self, config: Dict[str, Any]):
        #
        # Sanity check default scopes
        #
        self.__validate_default_scopes(config['default_scopes'])

        #
        # Parse tags
        #
        config['tags'] = self._parse_custom_tags(config)

        #
        # Parse custom metadata
        #
        config['metadata'] = self._parse_custom_metadata(config)

        #
        # DNS settings
        #
        config['dns_domain'] = config['dns_domain'] \
            if 'dns_domain' in config else self.private_dns_zone

        config['dns_search'] = config['dns_search'] \
            if 'dns_search' in config else self.private_dns_zone

        if not config['dns_nameservers']:
            config['dns_nameservers'].append(self.installer_public_ipaddress)

        # extract 'region' from 'zone'; partially validate zone as side-effect
        try:
            config['region'], _ = config['zone'].rsplit('-', 1)
        except ValueError:
            raise ConfigurationError(
                'Invalid format for \'region\' setting: {}'.format(
                    config['region'])
            )

        if 'network' in config:
            network_defs = config['network']

            del config['network']
        elif 'networks' in config:
            network_defs = config['networks']

            del config['networks']
        else:
            # if 'network' or 'networks' is not defined, fall back to legacy
            network_defs = ['default']

        # convert networks definition into list of tuples
        self.getLogger().debug('Parsing network configuration')

        config['networks'] = self.__parse_network_adapter_config(network_defs)

    def __parse_network_adapter_config(self, network_defs):
        return [split_three_item_value(network) for network in network_defs]

    def _parse_custom_tags(self, _configDict):
        """
        Raises:
            ConfigurationError
        """

        # Create common regex for validating tags and custom metadata keys
        regex = re.compile(r'[a-zA-Z0-9-_]{1,128}')

        # Parse custom tags
        tags = shlex.split(_configDict['tags']) \
            if 'tags' in _configDict and _configDict['tags'] else []

        # Validate custom tags
        for tag in tags:
            result = regex.match(tag)
            if result is None or result.group(0) != tag:
                errmsg = ('Tag [%s] does not match regex'
                          '\'[a-zA-Z0-9-_]{1,128}\'' % (tag))

                self.getLogger().error('' + errmsg)

                raise ConfigurationError(errmsg)

        return tags

    def _parse_custom_metadata(self, _configDict):
        """
        Raises:
            ConfigurationError
        """

        metadata = {}

        regex = re.compile(r'[a-zA-Z0-9-_]{1,128}')

        if 'metadata' in _configDict and _configDict['metadata']:
            # Support tag names/values containing spaces and tags without
            # value.
            for tagdef in shlex.split(_configDict['metadata']):
                key, value = tagdef.split(':', 1) \
                    if ':' in tagdef else (tagdef, '')

                result = regex.match(key)

                if result is None or result.group(0) != key:
                    errmsg = ('Metadata key [%s] must match regex'
                              ' \'[a-zA-Z0-9-_]{1,128}\'' % (key))

                    self.getLogger().error(errmsg)

                    raise ConfigurationError(errmsg)

                metadata = value

        return metadata

    def __init_session(self, section_name):
        """
        Initialize session (authorize with Google Compute Engine, etc)

        :raises ConfigurationError:
        :raises ResourceNotFound:
        """

        session = {}

        session['config'] = self.getResourceAdapterConfig(section_name)

        session['connection'] = gceAuthorize_from_json(
            session['config']['json_keyfile'])

        return session

    def __addIdleNodes(self, session, dbSession: Session, addNodesRequest,
                       dbHardwareProfile, dbSoftwareProfile): \
            # pylint: disable=unused-argument
        """
        Create new nodes in idle state

        Raises:
            UnsupportedOperation
        """

        self.getLogger().debug('__addIdleNodes()')

        added_nodes = []

        nodeCount = addNodesRequest['count'] \
            if 'count' in addNodesRequest else 1

        for _ in range(nodeCount):
            ip = None

            addNodeRequest = {}

            addNodeRequest['nics'] = [
                dict(device=dbHardwareProfileNetwork.networkdevice.name)
                for dbHardwareProfileNetwork in
                dbHardwareProfile.hardwareprofilenetworks]

            if ip is not None:
                addNodeRequest['nics'][0]['ip'] = ip

            node = self.nodeApi.createNewNode(
                None, addNodeRequest, dbHardwareProfile,
                dbSoftwareProfile)

            node.instance = InstanceMapping(
                resource_adapter_configuration=self.load_resource_adapter_config(
                    dbSession,
                    addNodesRequest['resource_adapter_configuration']
                )
            )

            added_nodes.append(node)

            self.getLogger().debug(
                'Created idle Google Compute Engine node [%s]' % (
                    node.name))

        return added_nodes

    def __getStartupScript(self, configDict):
        """
        Build a node/instance-specific startup script that will initialize
        VPN, install Puppet, and the bootstrap the instance.
        """

        self.getLogger().debug('__getStartupScript()')

        if not os.path.exists(configDict['startup_script_template']):
            self.getLogger().warning(
                'User data script template [%s] does not'
                ' exist. Compute Engine instances will be started without'
                ' user data' % (configDict['startup_script_template']))

            return None

        templateFileName = configDict['startup_script_template']

        installerIp = self.installer_public_ipaddress

        config = {
            'installerHostName': self.installer_public_hostname,
            'installerIp': installerIp,
            'adminport': str(self._cm.getAdminPort()),
            'scheme': self._cm.getAdminScheme(),
            'cfmuser': self._cm.getCfmUser(),
            'cfmpassword': self._cm.getCfmPassword(),
            'override_dns_domain': str(configDict['override_dns_domain']),
            'dns_options': quoted_val(configDict['dns_options'])
                           if configDict.get('dns_options', None) else None,
            'dns_search': quoted_val(configDict['dns_search']),
            'dns_nameservers': _get_encoded_list(
                configDict['dns_nameservers']),
        }

        with open(templateFileName) as fp:
            result = ''

            for inp in fp.readlines():
                if inp.startswith('### SETTINGS'):
                    result += '''\
installerHostName = '%(installerHostName)s'
installerIpAddress = '%(installerIp)s'
port = %(adminport)s
cfmUser = '%(cfmuser)s'
cfmPassword = '%(cfmpassword)s'

# DNS settings
override_dns_domain = %(override_dns_domain)s
dns_options = %(dns_options)s
dns_search = %(dns_search)s
dns_nameservers = %(dns_nameservers)s
''' % (config)
                else:
                    result += inp

        return result

    def __init_new_node(self, session: dict, dbSession: Session,
                        dbHardwareProfile: HardwareProfile,
                        dbSoftwareProfile: SoftwareProfile,
                        generate_ip: bool) -> Node: \
            # pylint: disable=no-self-use
        # Initialize Node object for insertion into database

        name = self.__generate_node_name(
            session, dbSession, dbHardwareProfile, generate_ip)

        node = Node(name=name)
        node.state = state.NODE_STATE_LAUNCHING
        node.isIdle = False
        node.hardwareprofile = dbHardwareProfile
        node.softwareprofile = dbSoftwareProfile

        return node

    def __createNodes(self, session: dict, dbSession: Session,
                      addNodesRequest: dict,
                      dbHardwareProfile: HardwareProfile,
                      dbSoftwareProfile: SoftwareProfile,
                      generate_ip: Optional[bool] = True) -> List[Node]: \
            # pylint: disable=unused-argument
        """
        Raises:
            ConfigurationError
            NetworkNotFound
        """

        self.getLogger().debug('__createNodes()')

        nodeCount = addNodesRequest['count'] \
            if 'count' in addNodesRequest else 1

        nodeList: List[Node] = []

        for _ in range(nodeCount):
            # Initialize new Node object
            node = self.__init_new_node(
                session,
                dbSession,
                dbHardwareProfile,
                dbSoftwareProfile,
                generate_ip=generate_ip)

            node.addHostSession = self.addHostSession

            # Add NIC to new node
            if generate_ip:
                # Use provisioning network from hardware profile
                hardwareprofilenetwork = get_provisioning_hwprofilenetwork(
                    dbHardwareProfile)

                ip = self.addHostApi.generate_provisioning_ip_address(
                    hardwareprofilenetwork.network)

                nic = Nic(ip=ip, boot=True)
                nic.networkId = hardwareprofilenetwork.network.id
                nic.network = hardwareprofilenetwork.network
                nic.networkdevice = hardwareprofilenetwork.networkdevice
                nic.networkDeviceId = hardwareprofilenetwork.networkDeviceId

                node.nics = [nic]

            nodeList.append(node)

        return nodeList

    def __generate_node_name(self, session: dict, dbSession: Session,
                             hardwareprofile: HardwareProfile,
                             generate_ip: bool):
        # Generate node host name

        fqdn = self.addHostApi.generate_node_name(
            dbSession,
            hardwareprofile.nameFormat, randomize=not generate_ip,
            dns_zone=self.private_dns_zone)

        if not generate_ip:
            if not False and \
                    hardwareprofile.location != 'remote-vpn':
                hostname, _ = fqdn.split('.', 1)

                if session['config']['override_dns_domain']:
                    dns_domain = self.private_dns_zone

                    if session['config']['dns_domain'] == dns_domain:
                        return fqdn
                elif '.' in self.installer_public_hostname:
                    dns_domain = \
                        self.installer_public_hostname.split('.', 1)[1]

                hostname, _ = fqdn.split('.', 1)

                return '{0}.{1}'.format(hostname, dns_domain)

        return '{0}.{1}'.format(hostname, session['config']['dns_domain'])

    def __process_error_response(self, instance_name, result):
        """
        Raises:
            CommandFailed
        """

        logmsg = ', '.join(
            '%s (%s)' % (error['message'], error['code'])
            for error in result['error']['errors'])

        excmsg = ', '.join(
            '%s' % (error['message'])
            for error in result['error']['errors'])

        self.getLogger().error(
            'Error launching instance [%s]: ' % (instance_name) + logmsg)

        raise CommandFailed(
            'Google Compute Engine reported error: \"%s\"' % (excmsg))

    def __build_node_request_queue(self, nodes): \
            # pylint: disable=no-self-use
        return [dict(node=node, status='pending') for node in nodes]

    def __write_user_data(self, node, user_data_yaml):
        dstdir = get_cloud_init_path(node.name.split('.', 1)[0])

        if not os.path.exists(dstdir):
            self.getLogger().debug(
                'Creating cloud-init directory [%s]' % (dstdir))

            os.makedirs(dstdir)

        with open(os.path.join(dstdir, 'user-data'), 'w') as fp:
            fp.write(user_data_yaml)

    def __get_instance_metadata(self, session, pending_node):
        node = pending_node['node']

        metadata = self.__get_metadata(session)

        # Default to using startup-script
        if 'startup_script_template' in session['config']:
            startup_script = self.__getStartupScript(session['config'])

            if startup_script:
                metadata.append(('startup-script', startup_script))

            # Uncomment this to create local copy of startup script
            # tmpfn = '/tmp/startup_script.py.%s' % (dbNode.name)
            # with open(tmpfn, 'w') as fp:
            #     fp.write(startup_script + '\n')
        else:
            self.getLogger().warning(
                'Startup script template not defined for hardware'
                ' profile [%s]' % (node.hardwareprofile.name))

        if session['config']['override_dns_domain']:
            metadata.append(('hostname', node.name))

        return metadata

    def __launch_instances(self, session, dbSession: Session, node_requests,
                           addNodesRequest, pre_launch_callback=None):
        # Launch Google Compute Engine instance for each node request

        self.getLogger().debug('__launch_instances()')

        common_launch_args = self.__get_common_launch_args(session)

        # 'preemptible' is passed through addNodesRequest as
        # an "extra" argument to 'add-nodes'
        common_launch_args['preemptible'] = \
            'extra_args' in addNodesRequest and \
            'preemptible' in addNodesRequest['extra_args']

        for node_request in node_requests:
            node_request['instance_name'] = get_instance_name_from_host_name(
                node_request['node'].name)

            try:
                metadata = self.__get_instance_metadata(session, node_request)
            except Exception:
                self.getLogger().exception(
                    'Error getting metadata for instance [%s] (%s)' % (
                        node_request['instance_name'],
                        node_request['node'].name))

                raise

            # Start the Compute Engine instance here

            if pre_launch_callback:
                try:
                    pre_launch_callback(node_request['instance_name'])
                except Exception:
                    self.getLogger().exception(
                        'Error calling pre-launch callback for instance'
                        ' [%s]' % (node_request['instance_name']))

                    raise

            #
            # Persistent disks must be created before the instances
            #
            persistent_disks = self.__process_added_disk_changes(
                session, node_request)

            #
            # 'disksize' setting is ignored if disks/partitions are defined
            # in the software profile.
            #
            if not persistent_disks:
                persistent_disks.append({
                    'sizeGb': session['config']['disksize'],
                })

            #
            # Now create the instances...
            #
            try:
                node_request['response'] = self.__launch_instance(
                    session,
                    node_request['instance_name'],
                    metadata,
                    common_launch_args,
                    persistent_disks=persistent_disks
                )

            except Exception:
                self.getLogger().error(
                    'Error launching instance [%s]' % (
                        node_request['instance_name']))

                raise

            # Update persistent mapping of node -> instance
            node_request['node'].instance = InstanceMapping(
                instance=node_request['instance_name'],
                instance_metadata=[
                    InstanceMetadata(
                        key='zone',
                        value=node_request['response']['zone'].split('/')[-1]
                    ),
                ],
                resource_adapter_configuration=self.load_resource_adapter_config(
                    dbSession,
                    addNodesRequest.get('resource_adapter_configuration')
                )
            )

        # Wait for instances to launch
        self.__wait_for_instances(session, node_requests)

    def __get_common_launch_args(self, session):
        """
        :raises OperationFailed:
        """

        common_launch_args = {}

        if 'image' in session['config']:
            if '/' in session['config']['image']:
                image_project, image_name = \
                    session['config']['image'].split('/', 1)
            else:
                image_project = None
                image_name = session['config']['image']

            common_launch_args['image_url'] = \
                self.__gce_get_image_by_name(
                    session['connection'].svc, image_project, image_name
                )
        elif 'image_family' in session['config']:
            if '/' in session['config']['image_family']:
                image_family_project, image_family = \
                    session['config']['image_family'].split('/', 1)
            else:
                image_family_project = None
                image_family = session['config']['image_family']

            common_launch_args['image_url'] = \
                self.__gce_get_image_family_url(
                    session['connection'].svc, image_family_project,
                    image_family,
                )
        else:
            common_launch_args['image_url'] = session['config']['image_url']

        common_launch_args['network_interfaces'] = \
            self.__get_network_interface_definitions(
                session['config']['project'],
                session['config']['region'],
                session['config']['networks'],
            )

        return common_launch_args

    def __process_added_disk_changes(self, session, node_request):
        persistent_disks = []

        node = node_request['node']

        # Apply any disk changes to VM before attempting to start
        diskChanges = self.sanApi.discoverStorageChanges(node)

        # Iterate over added disks in order
        for addedDiskNumber, disk in \
            [(int(disk_index), diskChanges['added'][disk_index])
             for disk_index in sorted(diskChanges['added'].keys())]:

            storageAdapter = disk['adapter']
            sizeMb = disk['size']
            sanVolume = disk['sanVolume']

            sizeGb = sizeMb / 1000

            if storageAdapter != 'default':
                # Ignore any non-default storage resources
                continue

            # Do physical disk create
            volName = get_disk_volume_name(
                node_request['instance_name'], addedDiskNumber)

            # Instance boot disk is created automatically when instance
            # is launched, so do not create one...
            if addedDiskNumber > 1:
                # Create persistent disk
                self.getLogger().debug(
                    'Creating data disk: (%s, %s, %s Gb)' % (
                        node.name, volName, sizeGb))

                response = self.__create_persistent_disk(
                    session, volName, sizeGb)

                # TODO: check result
                result = _blocking_call(
                    session['connection'].svc,
                    session['config']['project'],
                    response,
                    polling_interval=session['config']['sleeptime'])

                persistent_disks.append({
                    'name': volName,
                    'sizeGb': sizeGb,
                    'link': result['targetLink']
                })
            else:
                persistent_disks.append({
                    'name': volName,
                    'sizeGb': sizeGb
                })

            # Add placeholder to the storage subsystem so that drives
            # managed by GCE are tracked
            self.sanApi.addDrive(
                node, storageAdapter, addedDiskNumber, sizeMb, sanVolume)

        return persistent_disks

    def __wait_for_instance(self, session, pending_node_request):
        try:
            if gevent_wait_for_instance(session, pending_node_request):
                # VM launched successfully
                self.__instance_post_launch(session, pending_node_request)
            else:
                result = pending_node_request['result']

                logmsg = ', '.join(
                    '%s (%s)' % (error['message'], error['code'])
                    for error in result['error']['errors'])

                errmsg = 'Google Compute Engine error: \"%s\"' % (logmsg)

                self.getLogger().error('%s' % (errmsg))

                pending_node_request['status'] = 'error'
                pending_node_request['message'] = logmsg
        except Exception as exc:  # noqa pylint: disable=broad-except
            self.getLogger().exception(
                '_blocking_call() failed on instance [%s]' % (
                    pending_node_request['instance_name']))

            pending_node_request['status'] = 'error'
            pending_node_request['message'] = str(exc)

    def wait_worker(self, session, queue):
        # greenlet to wait on queue and process VM launches
        while True:
            pending_node_request = queue.get()

            try:
                self.__wait_for_instance(session, pending_node_request)
            finally:
                queue.task_done()

    def __wait_for_instances(self, session, node_request_queue):
        """
        Raises:
            CommandFailed
        """
        self.getLogger().debug('__wait_for_instances()')

        queue = JoinableQueue()

        launch_requests = len(node_request_queue)
        worker_thread_count = 10 if launch_requests > 10 else launch_requests

        # Create greenlets
        for _ in range(worker_thread_count):
            gevent.spawn(self.wait_worker, session, queue)

        for node_request in node_request_queue:
            if 'response' not in node_request:
                # Ignore failed launch
                continue

            queue.put(node_request)

        queue.join()

        # Raise exception if any instances failed
        for node_request in node_request_queue:
            if node_request['status'] == 'error':
                self.getLogger().error(
                    'Message: {0}'.format(node_request['message']))

                raise CommandFailed(
                    'Fatal error launching one or more instances')

    def __instance_post_launch(self, session, node_request):
        instance_name = node_request['instance_name']
        node = node_request['node']

        # Create nics for instance
        node.state = state.NODE_STATE_INSTALLED

        instance = self.__getInstance(session, instance_name)

        internal_ip = self.__get_instance_internal_ip(instance)

        # All nodes have a provisioning nic
        provisioning_nic = Nic(ip=internal_ip, boot=True)

        node.nics.append(provisioning_nic)

        if not self.is_running_on_gce:
            if node.hardwareprofile.location != 'remote-vpn':
                # Extract 'external' IP
                external_ip = self.__get_instance_external_ip(instance)

                if not external_ip:
                    self.getLogger().debug(
                        'Instance [%s] does not have an'
                        ' external IP' % (instance_name))

                    return

                self.getLogger().debug(
                    'Instance [%s] external IP [%s]' % (
                        instance_name, external_ip))

                external_nic = Nic(ip=external_ip, boot=False)

                node.nics.append(external_nic)

                ip = external_ip
        else:
            ip = provisioning_nic.ip

        # Call pre-add-host to set up DNS record
        self._pre_add_host(
            node.name,
            node.hardwareprofile.name,
            node.softwareprofile.name,
            ip)

    def __get_instance_internal_ip(self, instance): \
            # pylint: disable=no-self-use
        for network_interface in instance['networkInterfaces']:
            return network_interface['networkIP']

        return None

    def __get_instance_external_ip(self, instance): \
            # pylint: disable=no-self-use
        for network_interface in instance['networkInterfaces']:
            for accessConfig in network_interface['accessConfigs']:
                if accessConfig['kind'] == 'compute#accessConfig':
                    if accessConfig['name'] == 'External NAT' and \
                            accessConfig['type'] == 'ONE_TO_ONE_NAT':
                        return accessConfig['natIP']

        return None

    def __addActiveNodes(self, session: dict, dbSession: Session,
                         addNodesRequest: dict,
                         dbHardwareProfile: HardwareProfile,
                         dbSoftwareProfile: SoftwareProfile) -> List[Node]:
        """
        Create active nodes
        """

        self.getLogger().debug('__addActiveNodes()')

        # Always default to 1 node if 'count' is missing
        count = addNodesRequest['count'] if 'count' in addNodesRequest else 1

        self.getLogger().info(
            'Creating %d node(s) for mapping to Compute Engine'
            ' instance(s)' % (count))

        # Create node entries in the database
        nodes = self.__createNodes(
            session, dbSession, addNodesRequest, dbHardwareProfile,
            dbSoftwareProfile, generate_ip=False)

        dbSession.add_all(nodes)
        dbSession.commit()

        self.getLogger().debug(
            'Allocated node(s): %s' % (
                ' '.join([tmpnode.name for tmpnode in nodes])))

        try:
            node_request_queue = self.__build_node_request_queue(nodes)
        except Exception:
            self.getLogger().exception('Error building node request map')

            for node in nodes:
                dbSession.delete(node)

                self.__node_cleanup(node)

            dbSession.commit()

            raise

        # Launch instances
        try:
            self.__launch_instances(
                session, dbSession, node_request_queue, addNodesRequest)
        except Exception:
            # self.getLogger().exception('Error launching instances')

            self.__post_launch_action(dbSession, session, node_request_queue)

            raise

        return self.__post_launch_action(
            dbSession, session, node_request_queue)

    def __post_launch_action(self, dbSession, session, node_request_queue):

        count = len(node_request_queue)

        result = []
        completed = 0

        # Find all instances that failed to launch and clean them up

        for node_request in node_request_queue:
            if node_request['status'] != 'success':
                if 'instance_name' in node_request:
                    self.getLogger().error(
                        'Cleaning up failed instance [%s]'
                        ' (node [%s])' % (
                            node_request['instance_name'],
                            node_request['node'].name))
                else:
                    self.getLogger().error(
                        'Cleaning up node [%s]' % (node_request['node']))

                self.__node_cleanup(node_request['node'])

                dbSession.delete(node_request['node'])
            else:
                result.append(node_request['node'])

                # Mark node as 'Provisioned' after being successfully launched
                node_request['node'].state = state.NODE_STATE_PROVISIONED
                self.fire_provisioned_event(node_request['node'])

                completed += 1

        dbSession.commit()

        if completed and completed < count:
            warnmsg = ('only %d of %d requested instances launched'
                       ' successfully' % (completed, count))

            self.getLogger().warning('%s' % (warnmsg))

        return result

    def __get_metadata(self, session):
        metadata = []

        default_ssh_user = session['config']['default_ssh_user'] \
            if 'default_ssh_user' in session['config'] else 'centos'

        fn = '/root/.ssh/id_rsa.pub'

        if os.path.exists(fn):
            with open(fn) as fp:
                metadata.append(
                    ('sshKeys', '%s:' % (default_ssh_user) + fp.read()))
        else:
            self.getLogger().info(
                'Public SSH key (%s) not found' % (fn))

        metadata.append(('tortuga_installer_public_hostname',
                         self.installer_public_hostname))

        metadata.append(('tortuga_installer_public_ipaddress',
                         self.installer_public_ipaddress))

        for key, value in session['config']['metadata'].items():
            metadata.append((key, value))

        return metadata

    def __get_disk_type_resource_url(self, project, zone, ssd):
        project_url = '%s%s' % (GCE_URL, project)

        disk_type = 'pd-ssd' if ssd else 'pd-standard'

        return '%s/zones/%s/diskTypes/%s' % (project_url, zone, disk_type)

    def __create_persistent_disk(self, session, volume_name: str,
                                 size_in_Gb: int) -> None:
        self.getLogger.debug(
            f'Creating persistent disk [{volume_name}] (size [{size_in_Gb}])')

        # Create the instance
        session['connection'].svc.disks().insert(
            project=session['config']['project'],
            body={
                'kind': 'compute#disk',
                'name': volume_name,
                'sizeGb': size_in_Gb,
            },
            zone=session['config']['zone']
        ).execute()

    def __launch_instance(self, session, instance_name, metadata,
                          common_launch_args, persistent_disks=None):
        # This is the lowest level interface to Google Compute Engine
        # API to launch an instance.  It depends on 'session' (dict) to
        # contain settings, but this could easily be mocked.

        self.getLogger().debug(
            '__launch_instance(): instance_name=[%s]' % (instance_name))

        connection = session['connection']

        config = session['config']

        # Construct URLs
        project_url = '%s%s' % (GCE_URL, config['project'])

        machine_type_url = '%s/zones/%s/machineTypes/%s' % (
            project_url, config['zone'], config['type'])

        instance = {
            'name': instance_name,
            'tags': {
                'items': ['tortuga'] + config['tags'],
            },
            'machineType': machine_type_url,
            'disks': [
                {
                    'type': 'PERSISTENT',
                    'boot': 'true',
                    'mode': 'READ_WRITE',
                    # 'deviceName': instance_name,
                    'autoDelete': True,
                    'initializeParams': {
                        'sourceImage': common_launch_args['image_url'],
                        'diskSizeGb': persistent_disks[0]['sizeGb'],
                        'diskType': self.__get_disk_type_resource_url(
                            config['project'],
                            config['zone'],
                            config['ssd']
                        ),
                    }
                },
            ],
            'networkInterfaces': common_launch_args['network_interfaces'],
        }

        # only add 'preemptible' flag if enabled
        if common_launch_args['preemptible']:
            instance['scheduling'] = {
                'preemptible': common_launch_args['preemptible']
            }

        # Add any persistent (data) disks to the instance; ignore the first
        # disk in the disk because it's automatically created when the
        # instance is launched.

        # TODO: should the 'autoDelete' be exposed as a configurable?
        for persistent_disk in persistent_disks[1:] or []:
            instance['disks'].append({
                'type': 'PERSISTENT',
                'autoDelete': True,
                'source': persistent_disk['link'],
            })

        instance['metadata'] = {
            'kind': 'compute#metadata',
            'items': [dict(key=key, value=value) for key, value in metadata],
        }

        # Create the instance
        return connection.svc.instances().insert(
            project=config['project'],
            body=instance,
            zone=config['zone']
        ).execute()

    def __get_network_interface_definitions(self, project, region, networks):
        """
        Parse network(s) from config, return list of dicts containing
        network interface spec
        """

        network_interfaces = []

        for network in networks:
            network_interface, network_flags = \
                self.__get_network_interface(project, region, network)

            # honor 'ext[ernal]' network configuration flag
            if 'external' in network_flags and network_flags['external']:
                network_interface['accessConfigs'] = \
                    EXTERNAL_NETWORK_ACCESS_CONFIG

            network_interfaces.append(network_interface)

        # maintain backwards compatibility by ensuring the default interface
        # has external access. The semantics of this might need to change
        # in more advanced network configurations.
        enable_external_network_access(networks, network_interfaces)

        return network_interfaces

    def __get_network_interface(self, default_project, default_region, network):
        """
        Returns properly formed dict containing network interface
        configuration.
        """

        network_def, subnet_def, network_args = network

        # pay particular attention to the ordering reversal of input vs. output
        project, network = \
            split_forward_slash_value(network_def, default_project)

        network_interface = {
            'network': '%s%s/global/networks/%s' % (GCE_URL, project, network),
        }

        if subnet_def:
            # pay particular attention to the ordering reversal of input vs.
            # output
            region, subnetwork = \
                split_forward_slash_value(subnet_def, default_region)

            network_interface['subnetwork'] = \
                '%s%s/regions/%s/subnetworks/%s' % (
                    GCE_URL, project, region, subnetwork
                )

        return network_interface, get_network_flags(network_args)

    def __getInstance(self, session, instance_name):
        connection = session['connection']

        try:
            return connection.svc.instances().get(
                project=session['config']['project'],
                zone=session['config']['zone'],
                instance=instance_name
            ).execute()
        except apiclient.errors.HttpError as ex:
            # We can safely ignore a simple 404 error indicating the instance
            # does not exist.
            if ex.resp.status != 404:
                # Process JSON response content
                try:
                    error_resp = json.loads(ex.content)

                    self.getLogger().error(
                        'Unable to get Compute Engine instance %s'
                        ' (code: %s, message: %s)' % (
                            instance_name,
                            error_resp['error']['code'],
                            error_resp['error']['message']))
                except ValueError:
                    # Malformed JSON in response
                    self.getLogger().error(
                        'Unable to get Compute Engine instance %s'
                        ' (JSON parsing error)' % (instance_name))

            # If an exception was raised while attempting to get the instance,
            # return None to inform the caller that it is not available.
            response = None

        return response

    def __deleteInstance(self, session, node: Node):
        """
        Raises:
            CommandFailed
        """

        instance_name = get_instance_name_from_host_name(node.name)

        self.getLogger().debug(
            '__deleteInstance(): instance_name=[%s]' % (
                instance_name))

        project, zone = self.__get_project_and_zone_metadata(node)

        project_arg = project \
            if project is not None else session['config']['project']

        zone_arg = zone if zone is not None else session['config']['zone']

        try:
            initial_response = \
                session['connection'].svc.instances().delete(
                    project=project_arg,
                    zone=zone_arg,
                    instance=instance_name
                ).execute()

            self.getLogger().debug(
                '__deleteInstance(): initial_response=[%s]' % (
                    initial_response))

            # Wait for instance to be deleted
            # _blocking_call(
            #     session['connection'].svc,
            #     session['config']['project'], initial_response,
            #     polling_interval=session['config']['sleeptime'])
        except apiclient.errors.HttpError as ex:
            if ex.resp['status'] == '404':
                # Specified instance not found; nothing we can do there...
                self.getLogger().warning(
                    'Instance [%s] not found' % (instance_name))
            else:
                self.getLogger().debug(
                    '__deleteInstance(): ex.resp=[%s],'
                    ' ex.content=[%s]' % (ex.resp, ex.content))

                raise CommandFailed(
                    'Error deleting Compute Engine instance [%s]' % (
                        instance_name))

    def rebootNode(self, nodes: List[Node],
                   bSoftReset: Optional[bool] = False): \
            # pylint: disable=unused-argument
        """
        Reboot the given node
        """

        for node in nodes:
            if node.isIdle:
                self.getLogger().info(
                    'Ignoring reboot request for idle node [%s]' % (
                        node.name))

                continue

            self.getLogger().debug(
                'rebootNode(): node=[%s]' % (node.name))

            gce_session = self.__get_session(
                node.instance.resource_adapter_configuration.name
            )

            try:
                instance_name = get_instance_name_from_host_name(node.name)

                project, zone = self.__get_project_and_zone_metadata(
                    node
                )

                project_arg = project \
                    if project is not None else \
                    gce_session['config']['project']

                zone_arg = zone if zone is not None else \
                    gce_session['config']['zone']

                try:
                    initial_response = \
                        gce_session['connection'].svc.instances().reset(
                            project=project_arg, zone=zone_arg,
                            instance=instance_name
                        ).execute()

                    self.getLogger().debug(
                        'rebootNode(): initial_response=[%s]' % (
                            initial_response))

                    # Wait for instance to be rebooted
                    _blocking_call(
                        gce_session['connection'].svc,
                        gce_session['config']['project'],
                        initial_response,
                        polling_interval=gce_session['config']['sleeptime']
                    )

                    self.getLogger().debug(
                        f'Instance [{node.name}] rebooted')
                except apiclient.errors.HttpError as ex:
                    if ex.resp['status'] == '404':
                        # Specified instance not found; nothing we can do
                        # there...
                        self.getLogger().warning(
                            'Instance [%s] not found' % (instance_name))
                    else:
                        self.getLogger().debug(
                            'rebootNode(): ex.resp=[%s],'
                            ' ex.content=[%s]' % (ex.resp, ex.content))

                        raise CommandFailed(
                            'Error rebooting Compute Engine instance [%s]' % (
                                instance_name))
            finally:
                self.__release_session()

    def get_node_vcpus(self, name):
        """
        Return number of vcpus for node. Value of 'vcpus' configured
        in resource adapter configuration takes precedence over file
        lookup.

        Raises:
            ResourceNotFound

        :param name: node name
        :return: number of vcpus
        :returntype: int

        """
        #
        # Default to zero, because if for some reason the node can't be found
        # (i.e. it was deleted in the background), then it will not be using
        # any cpus
        #
        vcpus = 0

        try:
            configDict = self.get_node_resource_adapter_config(
                NodesDbHandler().getNode(self.session, name)
            )

            vcpus = configDict.get('vcpus', 0)
            if not vcpus:
                vcpus = self.get_instance_size_mapping(configDict['type'])

        except NodeNotFound:
            pass

        return vcpus

    def __gce_get_image_by_name(self, svc, image_project, image_name):
        """
        :raises OperationFailed: unable to find image
        """

        try:
            result = svc.images().get(
                project=image_project, image=image_name).execute()

            return result['selfLink']
        except googleapiclient.errors.HttpError as exc:

            errors = self.__process_exception(exc.content)

            if errors:
                self.getLogger().error(
                    'The following error(s) were reported:'
                )

                for err_message, err_reason, err_domain in errors:
                    self.getLogger().error(
                        '%s (reason: %s, domain: %s)',
                        err_message,
                        err_reason,
                        err_domain
                    )

        raise OperationFailed('Error reported by Google Compute Engine')

    def __gce_get_image_family_url(self, svc, image_family_project, image_family):
        """
        :raises OperationFailed:
        """

        try:
            result = svc.images().getFromFamily(
                project=image_family_project,
                family=image_family,
            ).execute()

            return result['selfLink']
        except googleapiclient.errors.HttpError as exc:

            errors = self.__process_exception(exc.content)

            if errors:
                self.getLogger().error(
                    'The following error(s) were reported:'
                )

                for err_message, err_reason, err_domain in errors:
                    self.getLogger().error(
                        '%s (reason: %s, domain: %s)',
                        err_message,
                        err_reason,
                        err_domain
                    )

        raise OperationFailed('Error reported by Google Compute Engine')

class GoogleComputeEngine:
    def __init__(self, svc=None):
        self._svc = None
        self.svc = svc

    @property
    def svc(self):
        return self._svc

    @svc.setter
    def svc(self, value):
        self._svc = value


def gceAuthorize_from_json(json_filename):
    url = 'https://www.googleapis.com/auth/compute'

    # Only try and load the file if it exists
    if os.path.isfile(json_filename):
        credentials = service_account.Credentials.from_service_account_file(
            json_filename, scopes=[url])
    else:
        # Try and fall back to machine credentials
        credentials = compute_engine.Credentials()

    svc = googleapiclient.discovery.build(
        'compute', API_VERSION, credentials=credentials)

    return GoogleComputeEngine(svc=svc)


def _blocking_call(gce_service, project_id, response,
                   polling_interval=Gce.DEFAULT_SLEEP_TIME):
    status = response['status']

    while status != 'DONE' and response:
        operation_id = response['name']

        # Identify if this is a per-zone resource
        if 'zone' in response:
            zone_name = response['zone'].split('/')[-1]

            response = gce_service.zoneOperations().get(
                project=project_id,
                operation=operation_id,
                zone=zone_name
            ).execute()
        else:
            response = gce_service.globalOperations().get(
                project=project_id, operation=operation_id
            ).execute()

        if response:
            status = response['status']

            if status != 'DONE':
                time.sleep(polling_interval)

    return response


def wait_for_instance(session, pending_node_request):
    result = _blocking_call(
        session['connection'].svc,
        session['config']['project'],
        pending_node_request['response'],
        polling_interval=session['config']['sleeptime']
    )

    pending_node_request['status'] = 'error' \
        if 'error' in result else 'success'

    pending_node_request['result'] = result

    return pending_node_request['status'] == 'success'


def _gevent_blocking_call(gce_service, project_id, response,
                          polling_interval: int = Gce.DEFAULT_SLEEP_TIME):
    """
    polling_interval is seconds
    """

    status = response['status']

    attempt = 0

    max_sleep_time = 5000

    while status != 'DONE' and response:
        operation_id = response['name']

        # Identify if this is a per-zone resource
        if 'zone' in response:
            zone_name = response['zone'].split('/')[-1]

            response = gce_service.zoneOperations().get(
                project=project_id,
                operation=operation_id,
                zone=zone_name
            ).execute()
        else:
            response = gce_service.globalOperations().get(
                project=project_id, operation=operation_id
            ).execute()

        if response:
            status = response['status']

            if status != 'DONE':
                if attempt > 0:
                    temp = min(max_sleep_time,
                               (polling_interval * 1000) * 2 ** attempt)

                    sleeptime = \
                        (temp / 2 + random.randint(0, temp / 2)) / 1000.0
                else:
                    # Set sleep time after launch to 10s
                    sleeptime = 10

                gevent.sleep(sleeptime)

        attempt += 1

    return response


def gevent_wait_for_instance(session, pending_node_request):
    result = _gevent_blocking_call(
        session['connection'].svc,
        session['config']['project'],
        pending_node_request['response'],
        polling_interval=session['config']['sleeptime']
    )

    pending_node_request['status'] = 'error' \
        if 'error' in result else 'success'

    pending_node_request['result'] = result

    return pending_node_request['status'] == 'success'


def is_running_on_gce() -> bool:
    p = subprocess.Popen('dmidecode -s bios-vendor', shell=True,
                         stdout=subprocess.PIPE)
    stdout, _ = p.communicate()

    return stdout.rstrip() == 'Google'


def _get_encoded_list(items):
    """Return Python list encoded in a string"""
    return '[' + ', '.join(['\'%s\'' % (item) for item in items]) + ']' \
        if items else '[]'


def quoted_val(value):
    return '\'{0}\''.format(value)


def split_forward_slash_value(value, default):
    """
    Returns '<default>/<value>' if value does not contain '/', otherwise
    '<token1>/<token2>'
    """

    if '/' in value:
        return tuple(value.split('/', 1))

    return default, value


def split_three_item_value(value) -> Tuple[str, Optional[str], Optional[str]]:
    token_count = value.count(':')

    if token_count == 2:
        return value.split(':', token_count)

    if token_count == 1:
        token1, token2 = value.split(':', token_count)

        return token1, token2, None

    return value, None, None


def get_network_flags(network_args):
    if network_args is None:
        return {}

    result = {}

    for network_arg in network_args.split(';'):
        if network_arg.lower().startswith('ext'):
            result['external'] = True
        elif network_arg.lower().startswith('noext'):
            result['external'] = False
        elif network_arg.lower().startswith('pri'):
            result['primary'] = True

    return result


def enable_external_network_access(networks, network_interfaces):
    if len(networks) != 1:
        return

    network_def, _, network_args = networks[0]

    network_flags = get_network_flags(network_args)

    if network_def == 'default' and \
            not network_args or \
            (network_args and
             'external' in network_flags and
             network_flags['external']):
        # ensure at least one interface has internet access enabled
        for network_interface in network_interfaces:
            if 'accessConfigs' in network_interface:
                # network configuration contains interface with external
                # (internet) access
                break
        else:
            network_interfaces[0]['accessConfigs'] = \
                EXTERNAL_NETWORK_ACCESS_CONFIG
