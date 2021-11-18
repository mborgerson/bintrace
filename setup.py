#!/usr/bin/env python
import subprocess
from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop as _develop

def build_common():
    subprocess.check_call(['./build.sh'])

class build(build_py):
    def run(self):
        build_common()
        return super().run()

class develop(_develop):
    def run(self):
        build_common()
        return super().run()

setup(
    name='bintrace',
    version='0.0.1',
    description='bintrace',
    cmdclass=dict(build_py=build, develop=develop),
    packages=['bintrace'],
    include_package_data=True,
    package_data={'bintrace': ['bin/*', 'trace.capnp']},
    scripts=['scripts/trace', 'scripts/trace-dbg'],
    install_requires=[
        'pycapnp',
        ]
    )
