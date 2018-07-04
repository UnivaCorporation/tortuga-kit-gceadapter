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

import mock
import pytest

from tortuga.resourceAdapter.gce \
    import Gce, ResourceAdapter
from tortuga.exceptions.configurationError import ConfigurationError


def myfunc(load_config_dict_mock, sectionName=None):
#     if sectionName == 'testing':
#         return {
#             'cloud_init_script_template': '/etc/resolv.conf',
#             'image_urn': 'value1:value2:value3:value4',
#         }
#
#     return {
#         'subscription_id': '123',
#         'client_id': '234',
#         'secret': 'password',
#         'tenant_id': '345',
#         'resource_group': 'resource-group',
#         'security_group': 'my-nsg',
#         'default_login': 'myuser',
#         'user_data_script_template': '/etc/hosts',
#         'ssh_key_value': 'ssh-rsa ...',
#         'image': 'myimage',
#         'use_managed_disks': 'true',
#     }

    return {
        'zone': 'the_zone',
        'type': 'the_type',
        'network': 'the_network',
        'project': 'the_project',
        'image_url': 'the_image_url',
        # /etc/resolv.conf was chosen because it's guaranteed to exist
        'json_keyfile': '/etc/resolv.conf',
    }


@mock.patch('tortuga.resourceAdapter.gce.Gce.private_dns_zone',
            new_callable=mock.PropertyMock)
@mock.patch.object(Gce, '_load_config_from_database', new=myfunc)
def test_default_config(private_dns_zone_mock):
    private_dns_zone_mock.return_value = 'example.com'

    adapter = Gce()

    config = adapter.getResourceAdapterConfig()

    assert not config['override_dns_domain']

    assert config['dns_domain'] == 'example.com'

    assert config['dns_search'] == config['dns_domain']


@mock.patch('tortuga.resourceAdapter.gce.Gce.private_dns_zone',
            new_callable=mock.PropertyMock)
@mock.patch.object(Gce, '_load_config_from_database', return_value={})
def test_invalid_empty_config(load_config_dict_mock, private_dns_zone_mock):
    private_dns_zone_mock.return_value = 'example.com'

    with pytest.raises(ConfigurationError):
        Gce().getResourceAdapterConfig()
