#!/bin/bash

EXT_IP=$(curl -f -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip 2>/dev/null)
if [ ! -z "$EXT_IP" ]; then
    echo "tortuga_gcp_external_ip=$EXT_IP"
fi
