#!/usr/bin/env python
# Copyright (c) 2018-2021 F5 Networks, Inc.
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

from setuptools import setup
from setuptools import find_packages
import f5_ctlr_agent


def parse_requirements(filename):
    """Parse requirements from a file."""
    with open(filename, 'r') as f:
        return [
            line.strip() for line in f
            if line.strip()
            and not line.startswith('#')
            and not line.startswith('-e')
            and not line.startswith('-')
        ]


install_reqs = parse_requirements('./agent-runtime-requirements.txt')

setup(
    name='f5-ctlr-agent',
    description='F5 Networks Controller Agent',
    license='Apache License, Version 2.0',
    version=f5_ctlr_agent.__version__,
    author='F5 Networks',
    url='https://github.com/charanm08/f5-ctlr-agent',
    keywords=['F5', 'big-ip'],
    scripts=['f5_ctlr_agent/bigipconfigdriver.py'],
    install_requires=install_reqs,
    packages=find_packages(exclude=['*test', '*.test.*', 'test*', 'test']),
)