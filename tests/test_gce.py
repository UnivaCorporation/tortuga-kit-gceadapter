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

import pprint

import tortuga.resourceAdapter.gce
from tortuga.db.softwareProfileDbApi import SoftwareProfileDbApi
from tortuga.db.hardwareProfileDbApi import HardwareProfileDbApi


def test_getConfig():
    hwProfileName = 'gce'
    swProfileName = 'BasicCompute'

    hwProfile = HardwareProfileDbApi().getHardwareProfile(hwProfileName)
    swProfile = SoftwareProfileDbApi().getSoftwareProfile(swProfileName)

    gceAdapter = tortuga.resourceAdapter.gce.Gce()

    configDict = gceAdapter._Gce__getConfig(
        resourceAdapterConfig={}, swProfile=swProfile, hwProfile=hwProfile)

    pprint.pprint(configDict)


def test_initSession():
    hwProfileName = 'gce'
    swProfileName = 'BasicCompute'

    hwProfile = HardwareProfileDbApi().getHardwareProfile(hwProfileName)
    swProfile = SoftwareProfileDbApi().getSoftwareProfile(swProfileName)

    gceAdapter = tortuga.resourceAdapter.gce.Gce()

    resourceAdapterConfig = {}

    session = gceAdapter._Gce__initSession(
        resourceAdapterConfig, swProfile=swProfile, hwProfile=hwProfile)

    return session

def test_launchActive():
    hwProfileName = 'gce'
    swProfileName = 'BasicCompute'

    hwProfile = HardwareProfileDbApi().getHardwareProfile(hwProfileName)
    swProfile = SoftwareProfileDbApi().getSoftwareProfile(swProfileName)

    gceAdapter = tortuga.resourceAdapter.gce.Gce()

    resourceAdapterConfig = {}

    session = gceAdapter._Gce__initSession(
        resourceAdapterConfig, swProfile=swProfile, hwProfile=hwProfile)

    nodeCreateDict = {
        'nodeCount': 5,
        'hardwareProfile': hwProfile,
        'softwareProfile': swProfile,
        'nodeDetails': [],
        'deviceName': None,
        'rackNumber': 1,
        'resourceUnits': 1,
        'supportedUnits': 1,
    }

    gceAdapter._Gce__launchActive(session, nodeCreateDict)


hwProfileName = 'gce'
swProfileName = 'BasicCompute'

hwProfile = HardwareProfileDbApi().getHardwareProfile(hwProfileName)
swProfile = SoftwareProfileDbApi().getSoftwareProfile(swProfileName)

gceAdapter = tortuga.resourceAdapter.gce.Gce()

session = gceAdapter._Gce__initSession(swProfile=swProfile, hwProfile=hwProfile)

# instance = gceAdapter._Gce__getInstance(session, instance_name='gce-02-local')

# for intfc in instance [u'networkInterfaces']:
#     for access_cfg in intfc[u'accessConfigs']:
#         print access_cfg[u'natIP']

# gceAdapter._Gce__deleteInstance(session, instance_name='gce-01-local')
# gceAdapter._Gce__deleteInstance(session, instance_name='gce-02-local')
# gceAdapter._Gce__deleteInstance(session, instance_name='gce-03-local')
# gceAdapter._Gce__deleteInstance(session, instance_name='gce-04-local')
# gceAdapter._Gce__deleteInstance(session, instance_name='gce-06-local')

# gceAdapter._Gce__create_persistent_disk(session, 'mike-was-here')
# gceAdapter._Gce__delete_persistent_disk(session, 'my-root-pd')
