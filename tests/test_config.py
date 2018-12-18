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


COMMON_CONFIG = {
    'zone': 'us-east1-b',
    'type': 'the_type',
    'network': 'the_network',
    'project': 'the_project',
    'image_url': 'the_image_url',
    'json_keyfile': '/etc/resolv.conf',
    'default_ssh_user': 'myuser',
    'startup_script_template': '/etc/resolv.conf',
}


def mock_load_config_from_database(load_config_dict_mock,
                                   sectionName: Optional[str] = None):
    """Return dict containing resource adapter configuration profile."""

    # /etc/resolv.conf was chosen because it's guaranteed to exist
    return COMMON_CONFIG


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


@mock.patch('tortuga.resourceAdapter.gceadapter.gce.Gce.private_dns_zone',
            new_callable=mock.PropertyMock)
def test_multiple_networks_config(private_dns_zone_mock):
    private_dns_zone_mock.return_value = 'example.com'

    config = dict(COMMON_CONFIG.items())

    config['networks'] = 'network1,network2'

    with mock.patch.object(
            Gce, '_load_config_from_database', return_value=config):
        adapter = Gce()

        result = adapter.getResourceAdapterConfig()

        assert 'networks' in result

        assert len(result['networks']) == 2

        assert isinstance(result['networks'][0], tuple)

        val1, val2, val3 = result['networks'][0]

        assert val1 == 'network1'

        assert val2 is None

        assert val3 is None


@mock.patch('tortuga.resourceAdapter.gceadapter.gce.Gce.private_dns_zone',
            new_callable=mock.PropertyMock)
def test_multiple_networks_config_advanced(private_dns_zone_mock):
    """Test for advanced network configuration."""

    private_dns_zone_mock.return_value = 'example.com'

    config = dict(COMMON_CONFIG.items())

    del config['image_url']

    config['image_family'] = 'image_project/image_family'

    config['networks'] = (
        'project1/network1::noexternal'
        ',project1/network2:region4/subnet5:external;primary'
    )

    with mock.patch.object(
            Gce, '_load_config_from_database', return_value=config):
        adapter = Gce()

        result = adapter.getResourceAdapterConfig()

        import ipdb; ipdb.set_trace()

        assert 'networks' in result

        assert len(result['networks']) == 2

        # validate first network
        val1, val2, val3 = result['networks'][0]

        assert val1 == 'project1/network1'

        assert not val2

        assert val3 == 'noexternal'

        # validate second network
        val4, val5, val6 = result['networks'][1]

        assert val4 == 'project1/network2'

        assert val5 == 'region4/subnet5'

        assert val6 == 'external;primary'
