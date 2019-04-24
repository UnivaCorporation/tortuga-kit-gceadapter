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

class tortuga_kit_gceadapter::gpu {
  package { ['kernel-devel', 'kernel-headers', 'epel-release']:
    ensure   => 'installed',
    provider => 'yum',
  }

  package { "cuda-repo-rhel7":
    provider => 'rpm',
    source   =>
      'http://developer.download.nvidia.com/compute/cuda/repos/rhel7/x86_64/cuda-repo-rhel7-10.0.130-1.x86_64.rpm'
    ,
    ensure   => 'installed',
  }

  package { ['cuda-10-0', ]:
    provider => 'yum',
    ensure   => 'installed',
    #require => 'tortuga_kit_uge::execd'
  }

  exec { "/bin/nvidia-smi -pm 1":
    subscribe => Package['cuda-10-0'],
  }

}
