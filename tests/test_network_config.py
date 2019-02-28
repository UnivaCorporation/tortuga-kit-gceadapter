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

import pytest

from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.resourceAdapter.gceadapter.gce import (Gce, get_network_flags,
                                                    is_network_flag_set)


@pytest.fixture(scope='session')
def adapter():
    return Gce()


def simple_network_cfg(adapter):
    # note: this test bypasses ResourceAdapter.getResourceAdapterConfig().
    # Network configuration setting must be formatted as if it had been
    # processed by getResourceAdapterConfig()

    network_cfg = [
        'network1:subnet1:external',
    ]

    return adapter._Gce__parse_network_adapter_config(network_cfg)


def simple_network_cfg_no_flags(adapter):
    # note: this test bypasses ResourceAdapter.getResourceAdapterConfig().
    # Network configuration setting must be formatted as if it had been
    # processed by getResourceAdapterConfig()

    network_cfg = [
        'network1:subnet1',
    ]

    return adapter._Gce__parse_network_adapter_config(network_cfg)


def multiple_network_cfg_no_flags(adapter):
    network_cfg = [
        'network1:subnet1',
        'network2:subnet2',
    ]

    return adapter._Gce__parse_network_adapter_config(network_cfg)


def multiple_network_cfg_with_external_on_network2(adapter):
    network_cfg = [
        'network1:subnet1',
        'network2:subnet2:external',
    ]

    return adapter._Gce__parse_network_adapter_config(network_cfg)


def test_parse_network_adapter_config(adapter):
    """Ensure single network configuration is parsed correctly."""

    networks = simple_network_cfg(adapter)

    assert isinstance(networks, list)

    assert len(networks) == 1, 'Multiple networks parsed; 1 expected'

    assert len(networks[0]) == 3, 'Unexpected elements in tuple'

    assert networks[0][0] == 'network1', 'Expected \'network1\''

    assert networks[0][1] == 'subnet1', 'Expected \'subnet1\''

    assert networks[0][2] == 'external', 'Expected \'external\''


def test_default_external(adapter):
    """Ensure external access (public IP) is assigned by default."""

    networks = simple_network_cfg_no_flags(adapter)

    network_intfcs = adapter._Gce__get_network_interface_definitions(
        'project1',
        'region1',
        networks
    )

    assert 'accessConfigs' in network_intfcs[0], \
        'Missing external access configuration'


def test_multiple_networks_defaults(adapter):
    """Multiple networks, no default flags"""
    networks = multiple_network_cfg_no_flags(adapter)

    assert not networks[0][2], 'Unexpected network flags for network1'

    assert not networks[1][2], 'Unexpected network flags for network2'


def test_multiple_networks_external(adapter):
    """Mulitple networks, external flag on network2"""
    networks = multiple_network_cfg_with_external_on_network2(adapter)

    network_intfcs = adapter._Gce__get_network_interface_definitions(
        'project1',
        'region1',
        networks
    )

    assert 'accessConfigs' not in network_intfcs[0], \
        'Unexpected network flags for network1'

    assert 'accessConfigs' in network_intfcs[1], \
        'Missing external flag on network2'


def test_multiple_networks_with_bad_config(adapter):
    """Test for condition where multiple network interfaces are marked as
    primary.
    """

    network_cfg = [
        'network1:subnet1:primary',
        'network2:subnet2:primary',
    ]

    networks = adapter._Gce__parse_network_adapter_config(network_cfg)

    with pytest.raises(ConfigurationError):
        adapter._Gce__get_network_interface_definitions(
            'project1',
            'region1',
            networks
        )


def test_is_network_flag_set():
    result = is_network_flag_set({'external': True}, flag='external')

    assert result

    result = is_network_flag_set({'external': False}, flag='external')

    assert not result

    result = is_network_flag_set({}, flag='external', default=True)

    assert result

    result = is_network_flag_set({}, flag='external', default=False)

    assert not result


def test_get_network_flags():
    result = get_network_flags('')
    assert not result

    result = get_network_flags('ext')
    assert 'external' in result and result['external']

    result = get_network_flags('external')
    assert 'external' in result and result['external']

    result = get_network_flags('pri')
    assert 'primary' in result and result['primary']

    result = get_network_flags('primary')
    assert 'primary' in result and result['primary']

    result = get_network_flags('noext')
    assert 'external' in result and not result['external']

    result = get_network_flags('noexternal')
    assert 'external' in result and not result['external']

    with pytest.raises(ConfigurationError):
        get_network_flags('invalid')

    result = get_network_flags('external;primary')
    assert 'external' in result and 'primary' in result and \
        result['external'] and result['primary']

    result = get_network_flags('external;noexternal')
    assert 'external' in result and not result['external']
