#!/usr/bin/env python
import subprocess
import sys
from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop as _develop
from pybind11.setup_helpers import Pybind11Extension, build_ext

__version__ = "0.0.1"

def get_include_dirs():
    if sys.platform == 'darwin':
        l = subprocess.check_output('pkg-config --cflags flatbuffers'.split(), encoding='utf-8')
        return [d[2:] for d in l.split() if d.startswith('-I')]
    else:
        return []

def build_common():
    subprocess.check_call('flatc -o events --python trace.fbs'.split(), cwd='bintrace')

class build(build_py):
    def run(self):
        build_common()
        return super().run()

class develop(_develop):
    def run(self):
        build_common()
        return super().run()

class custom_build_ext(build_ext):
    def run(self):
        subprocess.check_call('flatc --cpp ../bintrace/trace.fbs'.split(),
                              cwd='bintrace-native')
        super().run()

ext_modules = [
    Pybind11Extension("bintrace_native",
        ["bintrace-native/bintrace-native.cpp"],
        define_macros=[('VERSION_INFO', __version__)],
        include_dirs=get_include_dirs()
        ),
]

setup(
    name='bintrace',
    description='bintrace',
    version=__version__,
    packages=['bintrace', 'bintrace.events'],
    include_package_data=True,
    package_data={'bintrace': ['trace.fbs']},
    install_requires=['pybind11', 'flatbuffers'],
    ext_modules=ext_modules,
    cmdclass=dict(build_ext=custom_build_ext, build_py=build, develop=develop),
    zip_safe=False,
    python_requires=">=3.6",
    )
