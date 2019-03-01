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

import configparser
import logging
import os.path
import signal
import sys
import time

from daemonize import Daemonize
from tortuga.cli.tortugaCli import TortugaCli
from tortuga.config.configManager import ConfigManager
from tortuga.node.nodeApi import NodeApi
from tortuga.resourceAdapter.gceadapter.gce import Gce
from tortuga.db.dbManager import DbManager


POLLING_INTERVAL = 60

PIDFILE = '/var/run/gce_monitord.pid'


class SignalHandler(object):
    def __init__(self):
        pass

    def __enter__(self):
        self.interrupted = False
        self.released = False

        self.original_handler = signal.getsignal(signal.SIGTERM)

        def handler(signum, frame):
            self.release()
            self.interrupted = True

        signal.signal(signal.SIGTERM, handler)

        return self

    def __exit__(self, type, value, tb):
        self.release()

    def release(self):
        if self.released:
            return False

        signal.signal(signal.SIGTERM, self.original_handler)

        self.released = True

        return True


class AppClass(TortugaCli):
    """Main service 'application' class"""

    def __init__(self):
        super(AppClass, self).__init__()

        self._logger = logging.getLogger('tortuga.gce.gce_monitord')

        self._logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        ch = logging.handlers.TimedRotatingFileHandler(
            '/var/log/tortuga_gce_monitord', when='midnight')
        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self._logger.addHandler(ch)

        self.addOption('--daemonize', action='store_true', default=False,
                       help='Run service in background (daemonize)')

        self.addOption('--pidfile', default=PIDFILE,
                       help='Location of PID file')

        self.addOption(
            '--polling-interval', '-p', type=int,
            default=POLLING_INTERVAL,
            help='Polling interval in seconds (default: {})'.format(
                POLLING_INTERVAL
            )
        )

    def runCommand(self):
        self.parseArgs()

        self._logger.debug('Starting...')

        if not self.getArgs().daemonize:
            self.main()
        else:
            daemon = Daemonize(app=os.path.basename(sys.argv[0]),
                               pid=self.getArgs().pidfile,
                               action=self.main,
                               foreground=not self.getArgs().daemonize)

            daemon.start()

    def main(self):
        node_api = NodeApi()

        with SignalHandler() as sig_handler:
            with DbManager().session() as session:
                adapter = Gce()
                adapter.session = session

                session = adapter._Gce__get_session('default')

                while not sig_handler.interrupted:
                    deleted_nodes = []

                    cfg = configparser.ConfigParser()
                    cfg.read(os.path.join(
                        ConfigManager().getKitConfigBase(),
                        'gce-instance.conf'))

                    for node_name in cfg.sections():
                        instance_name = cfg.get(node_name, 'instance') \
                            if cfg.has_option(node_name, 'instance') else None

                        if instance_name is not None:
                            instance = adapter._Gce__getInstance(
                                session, instance_name)

                            if instance:
                                if instance['status'] == 'TERMINATED' and \
                                        instance['scheduling']['preemptible']:
                                    self._logger.debug(
                                        'Preemptible instance [{0}]'
                                        ' terminated'.format(instance_name))

                                    deleted_nodes.append(node_name)

                        if len(deleted_nodes) >= 10:
                            node_api.deleteNode(','.join(deleted_nodes))

                            deleted_nodes = []

                    if deleted_nodes:
                        node_api.deleteNode(session, ','.join(deleted_nodes))

                    time.sleep(self.getArgs().polling_interval)

        self._logger.debug('Exiting.')


def main():
    AppClass().run()
