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

"""Service to monitor Tortuga-managed Google Compute Engine preemptible
instances"""

import logging
import os.path
import sys
import time
from typing import Any, Dict, Iterator, NoReturn, Optional, Tuple

from daemonize import Daemonize
from tortuga.cli.tortugaCli import TortugaCli
from tortuga.db.dbManager import DbManager
from tortuga.objects.node import Node
from tortuga.resourceAdapter.gceadapter.gce import Gce
from tortuga.wsapi.metadataWsApi import MetadataWsApi
from tortuga.wsapi.nodeWsApi import NodeWsApi


POLLING_INTERVAL = 60

PIDFILE = '/var/run/gce_monitord.pid'


class AppClass(TortugaCli):
    """Main service 'application' class"""

    def __init__(self):
        super(AppClass, self).__init__()

        self._metadataWsApi = MetadataWsApi()
        self._nodeWsApi = NodeWsApi()

        self._logger = None

        self.addOption('--daemonize', action='store_true', default=False,
                       help='Run service in background (daemonize)')

        self.addOption('--pidfile', default=PIDFILE,
                       help='Location of PID file')

        self.addOption(
            '--polling-interval', '-p', type=int,
            default=POLLING_INTERVAL, metavar='SECONDS',
            help='Polling interval in seconds (default: {})'.format(
                POLLING_INTERVAL
            )
        )

    def parseArgs(self, usage: Optional[str] = None):
        super().parseArgs(usage=usage)

        self.__init_logger()

    def runCommand(self):
        self.parseArgs()

        self._logger.debug(
            'Polling interval: %ds',
            self.getArgs().polling_interval
        )

        if not self.getArgs().daemonize:
            self.main()
        else:
            Daemonize(
                app=os.path.basename(sys.argv[0]),
                pid=self.getArgs().pidfile,
                action=self.main,
                foreground=not self.getArgs().daemonize
            ).start()

    def __init_logger(self):
        self._logger = logging.getLogger('tortuga.gce.gce_monitord')

        self._logger.setLevel(logging.DEBUG)

        if self.getArgs().daemonize:
            # create console handler and set level to debug
            ch = logging.handlers.TimedRotatingFileHandler(
                '/var/log/tortuga_gce_monitord', when='midnight')

            # create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        else:
            ch = logging.StreamHandler()

            # create formatter
            formatter = logging.Formatter('%(levelname)s - %(message)s')

        ch.setLevel(logging.DEBUG)

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self._logger.addHandler(ch)

    def main(self) -> NoReturn:
        if self.getArgs().daemonize:
            self._logger.info('PIDFile: %s', self.getArgs().pidfile)

        with DbManager().session() as session:
            adapter = Gce()
            adapter.session = session

            while True:
                self.__process_preemptible_nodes(adapter)

                time.sleep(self.getArgs().polling_interval)

    def __process_preemptible_nodes(self, adapter: Gce):
        for instance_metadata, node in self.__iter_preemptible_nodes():
            adapter_cfg = \
                node.getInstance()['resource_adapter_configuration']['name']

            gce_session = adapter.get_gce_session(adapter_cfg)

            # call resource adapter to get vm instance
            vm_inst = adapter.gce_get_vm(
                gce_session,
                instance_metadata['instance']['instance']
            )

            if not is_vm_deleted_or_terminated(vm_inst):
                continue

            # GCE vm has been preempted, delete stale node record from Tortuga
            self._logger.info('Deleting node [%s]', node.getName())

            self._nodeWsApi.deleteNode(node.getName())

    def __iter_preemptible_nodes(self) \
            -> Iterator[Tuple[Dict[str, Any], Node]]:
        """Iterate over instance metadata, filtering out only records with
        'gce:scheduling' key set
        """
        for instance_metadata in \
                self._metadataWsApi.list(
                    filter_key='gce:scheduling'
                ):
            yield instance_metadata, \
                self.__get_node_by_metadata(instance_metadata)

    def __get_node_by_metadata(self, instance_metadata: dict) -> Node:
        """Return Node object by instance metadata
        """
        return self._nodeWsApi.getNode(
            instance_metadata['instance']['node']['name']
        )


def is_vm_deleted_or_terminated(vm_inst: Optional[dict]) -> bool:
    """Return whether or not a VM instance has been terminated or deleted.
    """
    return vm_inst is None or vm_inst['status'] == 'TERMINATED'


def main():
    AppClass().run()
