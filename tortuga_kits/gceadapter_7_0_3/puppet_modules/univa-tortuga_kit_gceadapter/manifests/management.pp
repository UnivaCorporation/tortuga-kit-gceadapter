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

class tortuga_kit_gceadapter::management::package {
  require tortuga::packages

  tortuga::pip_install { 'google-api-python-client': }
}

class tortuga_kit_gceadapter::management::post_install {
  require tortuga_kit_gceadapter::management::package

  include tortuga_kit_gceadapter::config

  tortuga::run_post_install { 'tortuga_kit_gce_management_post_install':
    kitdescr  => $tortuga_kit_gceadapter::config::kitdescr,
    compdescr => $tortuga_kit_gceadapter::management::compdescr,
  }
}

class tortuga_kit_gceadapter::management::config {
  require tortuga_kit_gceadapter::management::post_install

  include tortuga::config

  # FYI... the logic to install the Python packages has been moved into the
  # 'management' component post-install action.

  $instroot = $tortuga::config::instroot

  if versioncmp($::operatingsystemmajrelease, '7') < 0 {
    file { '/etc/rc.d/init.d/gce_monitord':
      content => template('tortuga_kit_gceadapter/gce_monitord.sysvinit.erb'),
      mode    => '0755',
    }
  } elsif versioncmp($::operatingsystemmajrelease, '7') >= 0 {
    # Install systemd service file on RHEL/CentOS 7.x

    file { '/usr/lib/systemd/system/gce_monitord.service':
      content => template('tortuga_kit_gceadapter/gce_monitord.service.erb'),
      mode    => '0644',
    } ~>
    exec { 'refresh_after_installing_gce_monitord_service':
      command     => '/bin/systemctl daemon-reload',
      refreshonly => true,
    }
  }

}

class tortuga_kit_gceadapter::management::service {
  require tortuga_kit_gceadapter::management::config

  if versioncmp($::operatingsystemmajrelease, '7') < 0 {
    $svcname = 'gce_monitord'
  } else {
    $svcname = 'gce_monitord.service'
  }

  service { $svcname:
    # ensure     => running,
    # enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}

class tortuga_kit_gceadapter::management {
  include tortuga_kit_gceadapter::config

  $compdescr = "management-${tortuga_kit_gceadapter::config::major_version}"

  # Install dependent packages, configure them, and restart Tortuga webservice
  contain tortuga_kit_gceadapter::management::package
  contain tortuga_kit_gceadapter::management::config
  contain tortuga_kit_gceadapter::management::service

  Class['tortuga_kit_gceadapter::management::config'] ~>
    Class['tortuga_kit_gceadapter::management::service']

  Class['tortuga_kit_gceadapter::management::config'] ~>
    Class['tortuga_kit_base::installer::webservice::server']
}
