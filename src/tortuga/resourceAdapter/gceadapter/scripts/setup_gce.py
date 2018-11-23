import os
import subprocess
from configparser import ConfigParser
from typing import Dict, List

import colorama
import requests

from tortuga.cli.tortugaCli import TortugaCli
from tortuga.db.dbManager import DbManager
from tortuga.exceptions.resourceNotFound import ResourceNotFound
from tortuga.resourceAdapter.resourceAdapter import \
    DEFAULT_CONFIGURATION_PROFILE_NAME
from tortuga.resourceAdapterConfiguration.api import \
    ResourceAdapterConfigurationApi


class APIError(Exception):
    pass


class ResourceAdapterSetup(TortugaCli):
    adapter_type = 'gce'
    verbose = False

    METADATA_URL = 'http://metadata.google.internal/computeMetadata/v1/'
    DEFAULT_SSH_USER = 'centos'
    DEFAULT_SCRIPT_TEMPLATE = 'startup_script.py'
    DEFAULT_IMAGE_TYPE = 'n1-standard-1'
    DEFAULT_NETWORK = 'default'
    DEFAULT_KEY_PATH = '/opt/tortuga/etc/gcloud-key.json'
    DEFAULT_DISK_SIZE = '10'

    def __init__(self):
        super().__init__()

        self._cli_path: str = self._find_cli()

    def parseArgs(self, usage=None):
        option_group_name = _('Setup options')
        self.addOptionGroup(option_group_name, '')

        self.addOptionToGroup(option_group_name,
                              '-v', '--verbose', dest='verbose',
                              default=False, action='store_true',
                              help='Verbose output')

        super().parseArgs(usage=usage)

    def runCommand(self):
        self.parseArgs()
        args = self.getArgs()
        self.verbose = args.verbose

        config: Dict[str, str] = self.get_config()

        self._write_config_to_file(config, DEFAULT_CONFIGURATION_PROFILE_NAME)
        self._write_config_to_db(config, DEFAULT_CONFIGURATION_PROFILE_NAME)

    def format(self, msg: str, *args, **kwargs):
        """
        Formats a message, with color.

        :param str msg:       the message to format
        :param *args:         args to pass to the str.format(...) method
        :param str forecolor: the colorama foreground color to use, defaults
                              to colorama.Fore.GREEN
        :param **kwargs:      kwargs to pass to the str.format(...) method

        :return: the formatted string

        """
        forecolor = colorama.Fore.GREEN
        if 'forecolor' in kwargs:
            forecolor = kwargs.pop('forecolor')

        formatted_args = []
        for arg in args:
            formatted_args.append(
                colorama.Fore.WHITE + str(arg) + forecolor
            )

        formatted_kwargs = {}
        for key, value in kwargs.items():
            formatted_kwargs[key] = \
                colorama.Fore.WHITE + str(value) + forecolor

        formatted_msg = forecolor + colorama.Style.BRIGHT + \
            msg.format(*formatted_args, **formatted_kwargs) + \
            colorama.Style.RESET_ALL

        return formatted_msg

    def format_white(self, msg, *args, **kwargs):
        """
        Formats a string with white as the foreground color. See format()
        for usage details.

        """
        kwargs['forecolor'] = colorama.Fore.WHITE
        return self.format(msg, *args, **kwargs)

    def format_error(self, msg, *args, **kwargs):
        """
        Formats a string with red as the foreground color. See format()
        for usage details.

        """
        kwargs['forecolor'] = colorama.Fore.RED
        return self.format(msg, *args, **kwargs)

    def _write_config_to_file(self, adapter_cfg: Dict[str, str],
                              profile: str):
        """
        Writes the resource adapter configuration to a config file in the
        tmp directory.

        :param adapter_cfg Dict[str, str]: the resource adapter configuration
        :param profile:                    the name of the resource adapter
                                           profile

        """
        section = 'resource-adapter' if profile == DEFAULT_CONFIGURATION_PROFILE_NAME else profile
        cfg = ConfigParser()
        cfg.add_section(section)

        for key, value in adapter_cfg.items():
            cfg.set(section, key, value)

        fn = '/tmp/adapter-defaults-{}.conf'.format(self.adapter_type)
        with open(fn, 'w') as fp:
            cfg.write(fp)

        print(self.format('Wrote resource adapter configuration: {}', fn))

    def _write_config_to_db(self, adapter_cfg: Dict[str, str],
                            profile_name: str):
        normalized_cfg = []
        for key, value in adapter_cfg.items():
            normalized_cfg.append({
                'key': key,
                'value': value,
            })

        api = ResourceAdapterConfigurationApi()
        with DbManager().session() as session:
            try:
                api.get(session, self.adapter_type, profile_name)
                print('Updating resource adapter configuration '
                      'profile: {}'.format(profile_name))
                api.update(session, self.adapter_type, profile_name,
                           normalized_cfg)

            except ResourceNotFound:
                print('Creating resource adapter configuration '
                      'profile {}'.format(profile_name))
                api.create(session, self.adapter_type, profile_name,
                           normalized_cfg)

    def _run_cmd(self, cmd: List[str], capture_stderr: bool = False) -> str:
        """
        Runs a command line program and returns the results.

        :param cmd List[str]: a list of command and arguments
        :return str:          the result

        """
        if self.verbose:
            print(' '.join(cmd))

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        err = stderr.decode().strip()
        if err:
            if capture_stderr:
                result = err

            else:
                raise Exception(err)

        else:
            result = stdout.decode().strip()

        if self.verbose:
            print(result)

        return result

    def _find_cli(self) -> str:
        """
        Looks for the Azure CLI.

        :return str: the path to the current CLI

        """
        cli_path = self._run_cmd(['which', 'gcloud'])
        if not cli_path:
            raise Exception('GCloud CLI not found')

        return cli_path

    def _run_gcloud(self, cmd: List[str], capture_stderr: bool = False) -> str:
        """
        Runs a GCloud CLI command and returns the result as a string.

        :param cmd List[str]: the az command to run

        :return str: the command result

        """
        gclound_cmd = [self._cli_path]
        gclound_cmd.extend(cmd)
        return self._run_cmd(gclound_cmd, capture_stderr).strip()

    def _get_keyfile(self):
        key_path = ResourceAdapterSetup.DEFAULT_KEY_PATH
        if not os.path.exists(key_path):
            print(self.format_error('Key file not found: {}', key_path))
            print(self.format(
                'To resolve this issue, please do the following:'))
            print(
                '  - Create a Google Cloud Service account in your project\n'
                '  - Generate a key for that service account\n'
                '  - Download the key as a JSON file\n'
                '  - Place that JSON file in the location specified above'
            )
            exit(0)
            pass

        #
        # Authenticate for future runs of the gcloud command
        #
        cmd = ['auth', 'activate-service-account',
               '--key-file={}'.format(key_path)]
        result = self._run_gcloud(cmd, capture_stderr=True)
        if 'Activated service account credentials' not in result:
            raise Exception(result)

        return key_path

    def _get_project(self):
        project = self._get_metadata('project/project-id')
        print(self.format('Project: {}', project))

        return project

    def _get_zone(self):
        zone_metadata = self._get_metadata('instance/zone')
        #
        # The zone metadata is returned in the following format:
        #
        #     projects/950338733423/zones/us-east1-b
        #
        zone = zone_metadata.split('/')[3]
        print(self.format('Zone: {}', zone))

        return zone

    def _get_network(self):
        network = ResourceAdapterSetup.DEFAULT_NETWORK
        print(self.format('Network: {}', network))

        return network

    def _get_image_url(self):
        cmd = ['compute', 'images', 'list', '--filter=name~"centos-7.*"',
               '--uri']
        url = self._run_gcloud(cmd)
        print(self.format('Image: {}', url))

        return url

    def _get_type(self):
        type_ = ResourceAdapterSetup.DEFAULT_IMAGE_TYPE
        print(self.format('Type: {}', type_))

        return type_

    def _get_metadata(self, path: str) -> str:
        headers = {
            'Metadata-Flavor': 'Google'
        }
        url = '{}{}'.format(ResourceAdapterSetup.METADATA_URL, path)
        r = requests.get(url, headers=headers)

        return r.text.strip()

    def get_config(self) -> Dict[str, str]:
        return {
            'json_keyfile': self._get_keyfile(),
            'project': self._get_project(),
            'zone': self._get_zone(),
            'network': self._get_network(),
            'image_url': self._get_image_url(),
            'type': self._get_type(),
            'default_ssh_user': ResourceAdapterSetup.DEFAULT_SSH_USER,
            'startup_script_template': ResourceAdapterSetup.DEFAULT_SCRIPT_TEMPLATE,
            'disksize': ResourceAdapterSetup.DEFAULT_DISK_SIZE
        }


def main():
    setup = ResourceAdapterSetup()
    setup.run()
