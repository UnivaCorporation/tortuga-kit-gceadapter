#!/usr/bin/env python

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

import os
import shutil

from tortuga.kit.mixins import ResourceAdapterMixin, logger
from tortuga.kit.installer import KitInstallerBase

class GceInstaller(ResourceAdapterMixin, KitInstallerBase):
    puppet_modules = ['univa-tortuga_kit_gceadapter']
    config_files = [
        'gce-instance-sizes.csv',
        'startup_script.py',
        'startup_script_bare.py',
    ]
    resource_adapter_name = 'gce'

    # Copy the custom facter fact to the appropriate place
    src_file = os.path.join(
        self.files_path,
        'tortuga_gcp_external_ip.sh'
    )
    dst_file = '/opt/puppetlabs/facter/facts.d/tortuga_gcp_external_ip.sh'

    #
    # Prevent existing file from being overwritten
    #
    if os.path.exists(dst_file):
        dst_file += '.new'

    logger.info(
        'Writing file: {}'.format(dst_file))

    shutil.copy2(src_file, dst_file)
