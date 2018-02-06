#!/usr/bin/env python

# Copyright 2018 F5 Networks Inc.
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
#

from pip.req import parse_requirements as parse_reqs
from setuptools import setup
from setuptools import find_packages

import f5_ctlr_agent

install_requirements = map(
    lambda x: str(x.req), parse_reqs('./requirements.txt', session='setup')
)

print('install requirements', install_requirements)
setup(
    name='f5-ctlr-agent',
    description='F5 Networks Controller Agent',
    license='Apache License, Version 2.0',
    version=f5_ctlr_agent.__version__,
    author='F5 Networks',
    url='https://github.com/f5devcentral/f5-ctlr-agent',
    keywords=['F5', 'big-ip'],
    scripts=['f5_ctlr_agent/bigipconfigdriver.py'],
    dependency_links=[
        'git+https://github.com/f5devcentral/f5-cccl.git@d55c2d24b03a50ecd71803501ea2db1dfed5efb5#egg=f5-cccl'
    ],
    install_requires=['f5-cccl']+install_requirements,
    packages=find_packages(exclude=['*test', '*.test.*', 'test*', 'test']),
)
