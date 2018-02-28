#!/bin/bash

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

VPN_ENDPOINT_NAME="navops-vpn"

echo "Deleting VPN routes..."
gcloud compute routes delete --quiet $VPN_ENDPOINT_NAME ${VPN_ENDPOINT_NAME}-client

echo "Deleting VPN instance..."
gcloud compute instances delete --quiet $VPN_ENDPOINT_NAME
