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
import subprocess
import time
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

def register_compute():
    runCommand('echo "%s" >> /.tortuga_execd' %(installerHostName))

def main():
    register_compute()

    if override_dns_domain:
        update_resolv_conf()

if __name__ == '__main__':
    main()
