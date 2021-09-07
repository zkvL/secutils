#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Secutils
# Copyright 2015 Yael Basurto
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import io
import os
import sys
from shutil import rmtree

from setuptools import find_packages, setup, Command

NAME = 'secutils'
DESCRIPTION = 'Small set of utilities that helps with report generation from security tools.'
URL = 'https://github.com/zkvL7/secutils'
EMAIL = 'zkvl@huitzek.mx'
AUTHOR = 'Yael | @zkvL7'
REQUIRES_PYTHON = '>=3.6.0'
VERSION = '3.5.0'

REQUIRED = [
    'colorama', 'requests', 'tqdm', 'xlsxwriter',
]

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description_content_type='text/markdown',
    author=AUTHOR,
    author_email=EMAIL,
    python_requires=REQUIRES_PYTHON,
    url=URL,
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    # If your package is a single module, use this instead of 'packages':
    # py_modules=['mypackage'],

    entry_points={
        'console_scripts': ['secutils=secutils:secutils.main'],
    },
    install_requires=REQUIRED,
    include_package_data=True,
    license='GNU',
    classifiers=[
        # Trove classifiers
        # Full list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.6',
    ],
)
