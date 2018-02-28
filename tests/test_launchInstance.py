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

from tortuga.resourceAdapter.gce import Gce, get_instance_name_from_host_name
from tortuga.db.dbManager import DbManager
from tortuga.db.nodesDbHandler import NodesDbHandler


gce = Gce()

session = DbManager().openSession()

node = NodesDbHandler().getNode(session, 'compute-04.private')

gce_session = gce._Gce__initSession(node.hardwareprofile)

instance_name = get_instance_name_from_host_name('compute-05.private')

instance_dict = gce._Gce__launchInstance(gce_session, instance_name)
