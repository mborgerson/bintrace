#!/usr/bin/env python
import subprocess
from setuptools import setup

setup(
    name='bintrace',
    version='0.0.1',
    description='bintrace',
    packages=['bintrace'],
    include_package_data=True,
    package_data={'bintrace': ['trace.capnp']},
    install_requires=[
        'pycapnp',
        ]
    )
