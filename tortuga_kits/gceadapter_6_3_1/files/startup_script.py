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

import os
import sys
import subprocess
import urllib2
import platform
import time
import base64
import json
import shutil


### SETTINGS


def runCommand(cmd, retries=1):
    for nRetry in range(retries):
        p = subprocess.Popen(cmd, shell=True)

        retval = p.wait()
        if retval == 0:
            break

        time.sleep(5 + 2 ** (nRetry * 0.75))
    else:
        return -1

    return retval


def _installPackage(pkgname, retries=10):
    if _isPackageInstalled(pkgname):
        return

    cmd = 'yum -y install %s' % (pkgname)

    retval = runCommand(cmd, retries)
    if retval != 0:
        raise Exception('Error installing package [%s]' % (pkgname))


def _isPackageInstalled(pkgname):
    return (runCommand('rpm --query --quiet %s' % (pkgname)) == 0)


def install_puppet(distro_maj_vers):
    pkgname = 'puppetlabs-release-pc1'

    url = 'http://yum.puppetlabs.com/%s-el-%s.noarch.rpm' % (
        pkgname, distro_maj_vers)

    bRepoInstalled = _isPackageInstalled(pkgname)

    if not bRepoInstalled:
        retval = runCommand('rpm -ivh %s' % (url), 5)
        if retval != 0:
            sys.stderr.write(
                'Error: unable to install package \"{0}\"\n'.format(pkgname))

            sys.exit(1)

    # Attempt to install puppet
    if not _isPackageInstalled('puppet-agent'):
        _installPackage('puppet-agent')


def set_hostname():
    url = 'https://%s:%s/v1/identify-node' % (installerIpAddress, port)

    req = urllib2.Request(url)

    req.add_header('Authorization',
                   'Basic ' + base64.standard_b64encode(
                       '%s:%s' % (cfmUser, cfmPassword)))

    for nCount in range(5):
        try:
            response = urllib2.urlopen(req)

            break
        except urllib2.URLError:
            pass
        except urllib2.HTTPError as ex:
            if ex.code == 401:
                sys.stderr.write('Invalid UniCloud webservice credentials\n')
                sys.exit(1)
            elif ex.code == 404:
                # Unrecoverable
                sys.stderr.write(
                    'URI not found; invalid UniCloud webservice'
                    ' configuration\n')
                sys.exit(1)

            time.sleep(2 ** (nCount + 1))
    else:
        sys.stderr.write('Unable to communicate with UniCloud webservice\n')
        sys.exit(1)

    try:
        d = json.load(response)

        if response.code != 200:
            if 'error' in d:
                errmsg = 'UniCloud webservice error: msg=[%s]' % (
                    error['message'])
            else:
                errmsg = 'UniCloud webservice internal error'

            raise Exception(errmsg)

        if 'node' not in d or 'name' not in d['node']:
            raise Exception('Malformed JSON response from UniCloud webservice')

        hostname = d['node']['name'].lower()
    except ValueError as exc:
        raise Exception('Unable to parse JSON response (reason=[%s])' % (exc))

    # TODO: this only applies to RHEL/CentOS <= 6
    runCommand('hostname %s' % (hostname))

    with open('/etc/sysconfig/network', 'a') as fp:
        fp.write('HOSTNAME=\"%s\"\n' % (hostname))

    return hostname


def update_resolv_conf():
    found_nameserver = False

    nss = dns_nameservers \
        if override_dns_domain else [installerIpAddress]

    fn= '/etc/resolv.conf'

    with open(fn) as fpIn:
        with open(fn + '.tortuga', 'w') as fpOut:
            fpOut.write('# Rewritten by Tortuga\n')

            for inbuf in fpIn.readlines():
                if inbuf.startswith('search '):
                    if not inbuf.startswith('search {0}'.format(dns_search)):
                        _, args = inbuf.rstrip().split('search', 1)

                        fpOut.write('search {0} {1}\n'.format(dns_search, args))
                elif inbuf.startswith('nameserver'):
                    if not found_nameserver:
                        fpOut.write('\n'.join(
                            ['nameserver {0}\n'.format(ns) for ns in nss]))
                        found_nameserver = True

                    fpOut.write(inbuf)

    shutil.move(fn, fn + '.orig')
    shutil.copyfile(fn + '.tortuga', fn)


def get_private_ip():
    cmd = ('ifconfig eth0 | grep \'inet \''
           ' | awk "{print \$2}" | sed "s/addr://"')

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

    result = p.communicate()

    ip = result[0].rstrip()

    return ip


def update_hosts_file(hostname):
    ip = get_private_ip()

    with open('/etc/hosts') as fpsrc:
        with open('/etc/hosts.new', 'w') as fpdst:
            for line in fpsrc.readlines():
                if line.startswith('#') or not line.rstrip():
                    fpdst.write(line)

                    continue

                host_ip, host_ent = line.split(' ', 1)

                if host_ip == ip:
                    fpdst.write('%-16s %s %s' % (host_ip, hostname, host_ent))
                else:
                    fpdst.write(line)

            # Add entry for Tortuga installer
            fpdst.write('%-16s %s\n' % (installerIpAddress, installerHostName))

            fpdst.write('169.254.169.254 metadata\n')

    if not os.path.exists('/etc/hosts.orig'):
        shutil.copy('/etc/hosts', '/etc/hosts.orig')

    shutil.copy('/etc/hosts.new', '/etc/hosts')

    os.unlink('/etc/hosts.new')


def wait_for_host(hostname):
    cmd = 'ping -c5 %s | grep -qv "0 received"' % (hostname)

    return runCommand(cmd, retries=5)


def bootstrap_puppet():
    cmd = ('/opt/puppetlabs/bin/puppet agent'
           ' --logdest /tmp/puppet_bootstrap.log'
           ' --onetime --server %s --waitforcert 120' % (installerHostName))

    runCommand(cmd)

def register_compute():
    runCommand('echo "%s" >> /.tortuga_execd' %(installerHostName))

def main():
    register_compute()
    vals = platform.dist()

    distro_maj_vers = vals[1].split('.')[0]

    if override_dns_domain:
        update_resolv_conf()

    install_puppet(distro_maj_vers)

    bootstrap_puppet()


if __name__ == '__main__':
    main()
