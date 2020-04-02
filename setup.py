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
import json
from setuptools import find_packages, setup


def get_version():
    with open('kit.json') as fp:
        kit_data = json.load(fp)
        return '{}+{}'.format(kit_data['version'], kit_data['iteration'])


setup(
    name='tortuga-gce-adapter',
    version=get_version(),
    url='http://univa.com',
    author='Univa Corporation',
    author_email='support@univa.com',
    license='Apache 2.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    namespace_packages=[
        'tortuga',
        'tortuga.resourceAdapter'
    ],
    zip_safe=False,
    install_requires=[
        'colorama',
        'google-api-python-client',
        'gevent',
        'requests',
        'daemonize',
    ],
    entry_points={
        'console_scripts': [
            'setup-gce=tortuga.scripts.setup_gce:main',
        ]
    }
)
