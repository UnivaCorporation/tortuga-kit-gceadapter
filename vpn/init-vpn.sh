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

# - local network/netmask must be specified using envvars LOCAL_NETWORK
#   and LOCAL_NETMASK
#
#   Examples:
#
#       LOCAL_NETWORK=192.168.33.0/24 ./init-vpn.sh
#       LOCAL_NETWORK=192.168.33.0/255.255.255.0 ./init-vpn.sh
#

if ! $(type -P gcloud &> /dev/null); then
    echo "Error: this script requires 'gcloud' (https://cloud.google.com/sdk/gcloud/)" >&2
    exit 1
fi

unattended=0

if [[ $1 == -y ]]; then
    unattended=1
fi

function cidr2mask()
{
  local maskpat="255 255 255 255"
  local maskdgt="254 252 248 240 224 192 128"
  set -- ${maskpat:0:$(( ($1 / 8) * 4 ))}${maskdgt:$(( (7 - ($1 % 8)) * 4 )):3}
  echo ${1-0}.${2-0}.${3-0}.${4-0}
}

function mask2cdr()
{
  # Assumes there's no "255." after a non-255 byte in the mask
  local x=${1##*255.}
  set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
  x=${1%%$3*}
  echo $(( $2 + (${#x}/4) ))
}

# Determine Google Compute Engine parameters
if [[ -z $GCE_REGION ]]; then
    readonly GCE_REGION=$(gcloud config list --format="value(compute["region"])" 2>/dev/null)

    if [[ $GCE_REGION == None ]]; then
        echo "Error: Google Compute Engine default 'region' not set. Use GCE_REGION to specify region" 2>&1
        exit 1
    fi
fi

# Validate region
gcloud compute regions list | grep --quiet ^$GCE_REGION
if [[ $? -ne 0 ]]; then
    echo "Error: Google Compute Engine region \"$GCE_REGION\" is invalid" >&2
    exit 1
fi

if [[ -z $GCE_ZONE ]]; then
    readonly GCE_ZONE=$(gcloud config list --format="value(compute["zone"])" 2>/dev/null)

    if [[ $GCE_ZONE == None ]]; then
        echo "Error: Google Compute Engine default 'zone'  not set. Use GCE_ZONE to specify zone" >&2
        exit 1
    fi
fi

readonly region_for_zone=$(gcloud compute zones list $GCE_ZONE --format="value(region)")

if [[ -z $region_for_zone ]]; then
    echo "Error: Google Compute Engine zone \"$GCE_ZONE\" not found" >&2
    exit 1
fi

if [[ $region_for_zone != $GCE_REGION ]]; then
    echo "Error: Region \"${GCE_REGION}\" is incompatible with zone ${GCE_ZONE}" >&2
    exit 1
fi

readonly server_certdir=$TORTUGA_ROOT/etc/certs/openvpn-server
readonly client_certdir=$TORTUGA_ROOT/etc/certs/openvpn-client
readonly cacertdir=$TORTUGA_ROOT/etc/CA
readonly VPN_NETWORK=${VPN_NETWORK:-10.8.0.0}
readonly VPN_NETMASK=${VPN_NETMASK:-255.255.255.0}
readonly VPN_CIDR=$(mask2cdr ${VPN_NETMASK})
readonly GCE_NETWORK=${GCE_NETWORK:-default}
readonly INSTANCE_NAME=${INSTANCE_NAME:-navops-vpn}
readonly LOCAL_NETWORK=${LOCAL_NETWORK:-192.168.1.0/255.255.255.0}

readonly LOCAL_NETWORK_ONLY=$(echo $LOCAL_NETWORK | cut -f1 -d/)
LOCAL_NETMASK_ONLY=$(echo $LOCAL_NETWORK | cut -f2 -d/)

if [[ $LOCAL_NETMASK_ONLY == ${LOCAL_NETMASK_ONLY//.} ]]; then
    if [[ $LOCAL_NETMASK_ONLY -lt 0 ]] || [[ $LOCAL_NETMASK_ONLY -gt 32 ]]; then
        echo "Error: invalid value for CIDR" >&2
        exit 1
    fi

    readonly LOCAL_CIDR=$LOCAL_NETMASK_ONLY

    readonly LOCAL_NETMASK_ONLY=$(cidr2mask $LOCAL_NETMASK_ONLY)
else
    readonly LOCAL_CIDR=$(mask2cdr $LOCAL_NETMASK_ONLY)
fi

# Check if instance already running
if [[ -n $(gcloud compute instances list ${INSTANCE_NAME} --format="value(name)" 2>/dev/null) ]]; then
    echo "Google Compute Engine instance \"${INSTANCE_NAME}\" already running..."
    exit 1
fi

# Create keys and certificates

if [[ ! -d $TORTUGA_ROOT/etc/certs/openvpn-server ]]; then
    # Create server certificates
    $TORTUGA_ROOT/bin/mkcert.sh --server --destdir $TORTUGA_ROOT/etc/certs/openvpn-server --host-name server server
    if [[ $? -ne 0 ]]; then
        echo "Error creating OpenVPN server key and certificate" >&2
        exit 1
    fi
fi

if [[ ! -d $TORTUGA_ROOT/etc/certs/openvpn-client ]]; then
    # Create client key and certificate
    $TORTUGA_ROOT/bin/mkcert.sh --destdir $TORTUGA_ROOT/etc/certs/openvpn-client --host-name client client
    if [[ $? -ne 0 ]]; then
        echo "Error creating OpenVPN client key and certificate" >&2
        exit 1
    fi
fi

if [[ ! -f /etc/openvpn/dh2048.pem ]]; then
    echo "Creating Diffie Hellman parameters"
    openssl dhparam -out /etc/openvpn/dh2048.pem 2048
    if [[ $? -ne 0 ]]; then
        echo "Error creating Diffie Hellman parameters" >&2
        exit 1
    fi
fi

if [[ -n $GCE_ZONE ]]; then
  create_args+=" --zone $GCE_ZONE"
fi

if [[ -n $GCE_PROJECT ]]; then
  create_args+=" --project $GCE_PROJECT"
fi

if [[ -n $GCE_NETWORK ]] && [[ $GCE_NETWORK != default ]]; then
  create_args+=" --network $GCE_NETWORK"
fi

routes_create_args=

if [[ -n $GCE_NETWORK ]] && [[ $GCE_NETWORK != default ]]; then
    routes_create_args+=" --network=$GCE_NETWORK"
fi

if [[ $(gcloud compute networks describe $GCE_NETWORK --format="value(x_gcloud_mode)") == legacy ]]; then
    remote_address=$(gcloud compute networks describe $GCE_NETWORK --format='value(IPv4Range)')
else
    remote_address=$(gcloud compute networks subnets list --network $GCE_NETWORK --regions $GCE_REGION --format="value(ipCidrRange)")
fi

if [ $? -ne 0 ]; then
    echo "Error: unable to query network \"${GCE_NETWORK}\" using gcloud; check credentials/authentication and try again" >&2
    exit 1
fi

readonly REMOTE_NETWORK=$(echo $remote_address | cut -f1 -d/)
readonly REMOTE_NETMASK=$(cidr2mask $(echo $remote_address | cut -f2 -d/))

echo
echo "                 VPN network: ${VPN_NETWORK}/${VPN_NETMASK}"
echo "               Local network: ${LOCAL_NETWORK_ONLY}/${LOCAL_NETMASK_ONLY}"
echo "       Compute Engine region: ${GCE_REGION}"
echo "         Compute Engine zone: ${GCE_ZONE}"
echo "Compute Engine instance name: ${INSTANCE_NAME}"
if [[ -n $GCE_PROJECT ]]; then
    echo "      Compute Engine project: ${GCE_PROJECT}"
fi
echo "      Compute Engine network: ${GCE_NETWORK} (${REMOTE_NETWORK}/${REMOTE_NETMASK})"
echo

if [[ $unattended -ne 1 ]]; then
    echo "Warning: this script will start a Google Compute Engine instance"
    echo
    echo -n "Do you wish to proceed [N/y]? "
    read PROMPT

    if [[ -z $PROMPT ]] || [[ $(echo $PROMPT | tr [YN] [yn] | cut -c1) != "y" ]]; then
        exit 1
    fi
fi


echo -n "Creating OpenVPN server configuration..."

sed -e "s/@VPN_NETWORK@/$VPN_NETWORK/" \
    -e "s/@VPN_NETMASK@/$VPN_NETMASK/" \
    -e "s/@REMOTE_NETWORK@/$REMOTE_NETWORK/" \
    -e "s/@REMOTE_NETMASK@/$REMOTE_NETMASK/" \
    -e "s/@LOCAL_NETWORK@/$LOCAL_NETWORK_ONLY/" \
    -e "s/@LOCAL_NETMASK@/$LOCAL_NETMASK_ONLY/" \
    < server.conf.tmpl >server.conf

if [[ $? -ne 0 ]]; then
    echo "failed."

    exit 1
fi

echo "done."

echo -n "Creating startup script... "

sed -e "s/@server_key@/$(base64 -w0 $server_certdir/server.key)/" \
    -e "s/@server_crt@/$(base64 -w0 $server_certdir/server.crt)/" \
    -e "s/@ca_crt@/$(base64 -w0 $cacertdir/ca.pem)/g" \
    -e "s/@server_conf@/$(base64 -w0 server.conf)/g" \
    -e "s/@dh2048_pem@/$(base64 -w0 /etc/openvpn/dh2048.pem)/" \
    -e "s/@LOCAL_NETWORK@/$LOCAL_NETWORK_ONLY/" \
    -e "s/@LOCAL_NETMASK@/$LOCAL_NETMASK_ONLY/" \
    < startup-script.sh.tmpl >startup-script.sh

if [[ $? -ne 0 ]]; then
  echo "failed."
  exit 1
fi

echo "done."

echo "Starting OpenVPN endpoint on Google Compute Engine... "

gcloud compute instances create $INSTANCE_NAME \
    $create_args \
    --image centos-7 \
    --machine-type f1-micro \
    --can-ip-forward \
    --metadata-from-file startup-script=startup-script.sh \

gcloud compute routes create navops-vpn \
    $routes_create_args \
    --destination-range $VPN_NETWORK/$VPN_CIDR \
    --next-hop-instance $INSTANCE_NAME

gcloud compute routes create navops-vpn-client \
    $routes_create_args \
    --destination-range $LOCAL_NETWORK_ONLY/$LOCAL_CIDR \
    --next-hop-instance $INSTANCE_NAME

remote_ip=$(gcloud compute instances list $INSTANCE_NAME --format=text | grep natIP | awk '{print $2}')

sed -e "s/@remote_ip@/$remote_ip/" < client.conf.tmpl >client.conf

echo
echo "Copy client.conf to /etc/openvpn/client.conf and run 'systemctl start openvpn@client' to start"
echo
echo "Ensure port 1194/udp is open in Google Compute Engine \"Firewall rules\""
echo
