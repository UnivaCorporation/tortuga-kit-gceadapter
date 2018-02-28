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

from tortuga.resourceAdapter.gce import Gce
from tortuga.db.dbManager import DbManager
from tortuga.db.nodesDbHandler import NodesDbHandler
from tortuga.db.hardwareProfilesDbHandler import HardwareProfilesDbHandler


def main():
    gce = Gce()

    session = DbManager().openSession()

    # Find first hardware profile that has 'gce' as the resource adapter
    for hwprofile in \
            HardwareProfilesDbHandler().getHardwareProfileList(session):
        if hwprofile.resourceadapter and \
           hwprofile.resourceadapter.name == 'gce':
            break
    else:
        raise Exception(
            'No hardware profile found with Google Compute Engine resource'
            ' adapter enabled')

    print(('Using hardware profile \'%s\''
           ' (use --hardware-profile to override)' % (hwprofile.name)))

    # Find first software profile mapped to hardware profile
    swprofile = hwprofile.mappedsoftwareprofiles[0]

    print(('Using software profile \'%s\''
           ' (use --software-profile to override)' % (swprofile.name)))

    gce_session = gce._Gce__initSession(hwprofile)

    # gce._Gce__launchInstance(gce_session, instance_name)

    addNodesRequest = {
        'count': 1,
        # 'nodeDetails': [
        #     {
        #         'name': 'compute-05.private',
        #     },
        # ],
    }

    gce._Gce__addActiveNodes(
        gce_session, session, addNodesRequest, hwprofile, swprofile)


if __name__ == '__main__':
    main()
