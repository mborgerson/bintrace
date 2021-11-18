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
    name='bintrace-qemu',
    version='0.0.1',
    description='bintrace QEMU tracer',
    cmdclass=dict(build_py=build, develop=develop),
    packages=['bintrace-qemu'],
    include_package_data=True,
    package_data={'bintrace-qemu': ['bin/*']},
    scripts=['scripts/bintrace-qemu', 'scripts/bintrace-qemu-dbg'],
    install_requires=[
        'bintrace',  # For trace protocol
        ]
    )
