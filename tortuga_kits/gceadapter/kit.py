#!/usr/bin/env python

# Copyright 2008-2020 Univa Corporation
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

from tortuga.kit.mixins import ResourceAdapterMixin
from tortuga.kit.installer import KitInstallerBase

class GceInstaller(ResourceAdapterMixin, KitInstallerBase):
    puppet_modules = ['univa-tortuga_kit_gceadapter']
    config_files = [
        'gce-instance-sizes.csv',
        'startup_script.py',
        'startup_script_bare.py',
        'bootstrap-aws-centos7.py',
        'bootstrap-aws-centos8.py',
        'bootstrap-aws-ubuntu18.py',
    ]
    resource_adapter_name = 'GCP'

    def  action_post_install(self, *args, **kwargs):
        # Call super class to make sure we do the standard post install
        # stuff
        super().action_post_install(*args, **kwargs)

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

        shutil.copy2(src_file, dst_file)
