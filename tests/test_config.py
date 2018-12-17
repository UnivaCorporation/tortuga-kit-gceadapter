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

from typing import Optional

import mock
import pytest

from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.resourceAdapter.gceadapter.gce import Gce


def mock_load_config_from_database(load_config_dict_mock,
                                   sectionName: Optional[str] = None):
    """Return dict containing resource adapter configuration profile."""

    # /etc/resolv.conf was chosen because it's guaranteed to exist
    return {
        'zone': 'the_zone',
        'type': 'the_type',
        'network': 'the_network',
        'project': 'the_project',
        'image_url': 'the_image_url',
        'json_keyfile': '/etc/resolv.conf',
        'default_ssh_user': 'myuser',
        'startup_script_template': '/etc/resolv.conf',
    }


@mock.patch('tortuga.resourceAdapter.gceadapter.gce.Gce.private_dns_zone',
            new_callable=mock.PropertyMock)
@mock.patch.object(Gce, '_load_config_from_database',
                   new=mock_load_config_from_database)
def test_default_config(private_dns_zone_mock):
    private_dns_zone_mock.return_value = 'example.com'

    adapter = Gce()

    config = adapter.getResourceAdapterConfig()

    assert not config['override_dns_domain']

    assert config['dns_domain'] == 'example.com'

    assert config['dns_search'] == config['dns_domain']


@mock.patch('tortuga.resourceAdapter.gceadapter.gce.Gce.private_dns_zone',
            new_callable=mock.PropertyMock)
@mock.patch.object(Gce, '_load_config_from_database', return_value={})
def test_invalid_empty_config(load_config_dict_mock, private_dns_zone_mock):
    with pytest.raises(ConfigurationError):
        Gce().getResourceAdapterConfig()
