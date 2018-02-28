`init-vpn.sh` assumes `gcloud` is currently installed and configured.

It is recommended to run `init-vpn.sh` from `$TORTUGA_ROOT/kits/kit-gce-*/vpn` by changing into that directory first:

    cd $TORTUGA_ROOT/kits/kit-gce-*/vpn
    <ENVVAR=...> ./init-vpn.sh <OPTIONS>

Assuming your local network is 192.168.0.0/24, run the following:

    LOCAL_NETWORK=192.168.0.0/24 ./init-vpn.sh

This will automatically create an OpenVPN endpoint in Google Compute Engine, set routing from remote instances on the 'default' network to the local `192.168.0.0/24` network.

If using a different network, specify it using `GCE_NETWORK`:

    LOCAL_NETWORK=192.168.0.0/24 GCE_NETWORK=notdefault ./init-vpn.sh

To use a different network for the VPN, use `VPN_NETWORK` and `VPN_NETMASK`:

    VPN_NETWORK=10.9.0.0 VPN_NETMASK=255.255.255.0 ./init-vpn.sh

The default is `10.8.0.0/24`.  Ensure the `VPN_NETWORK` does not conflict with the Google Compute Engine network.

Copy the generated `client.conf` file to `/etc/openvpn` and start the VPN as follows:

    systemctl start openvpn@client

### Firewall Rules ###

It is necessary to create firewall rule(s) to allow access, if using a network other than *default*.  These firewall rules are created by default for the *default* network.

Allow access between Google Compute Engine instances on network `10.128.0.0/20`:

    gcloud compute firewall-rules create navops-allow-internal \
        --source-ranges 10.128.0.0/20 --allow "tcp:1-65535,udp:1-65535,icmp"

Allow access from VPN network `10.8.0.0/24`:

    gcloud compute firewall-rules create navops-allow-vpn \
        --source-ranges 10.8.0.0/24 --allow "tcp:1-65535,udp:1-65535,icmp"
