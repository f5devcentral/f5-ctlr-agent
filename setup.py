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

# NOTE: This package needs to be installed with pip --process-dependency-links

install_reqs = []
install_links = []
install_gen = parse_reqs('./requirements.txt', session='setup')

for req in install_gen:
    install_reqs.append(str(req.req))
    if req.link is not None:
        install_links.append(str(req.link) + '-0')

print('install requirements', install_reqs)
setup(
    name='f5-ctlr-agent',
    description='F5 Networks Controller Agent',
    license='Apache License, Version 2.0',
    version=f5_ctlr_agent.__version__,
    author='F5 Networks',
    url='https://github.com/f5devcentral/f5-ctlr-agent',
    keywords=['F5', 'big-ip'],
    scripts=['f5_ctlr_agent/bigipconfigdriver.py'],
    dependency_links=install_links,
    install_requires=install_reqs,
    packages=find_packages(exclude=['*test', '*.test.*', 'test*', 'test']),
)
