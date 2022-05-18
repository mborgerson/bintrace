bintrace
========

* Tools to collect and analyze execution traces.
  * Plugin (and patches) to get execution traces from QEMU.
  * Python library to work with those traces.
  * Only intended to be run on Linux, for now. API likely to change.

```bash
sudo apt install flatbuffers-compiler libflatbuffers-dev
git clone https://github.com/mborgerson/bintrace
pip install build
cd bintrace
python -m build
pip install dist/*.whl              # install bintrace, for trace analysis
pip install -f dist ./bintrace-qemu # install bintrace qemu tracer, for trace collection
bintrace-qemu /usr/bin/uname -a     # produces uname.trace in current dir
python -m bintrace uname.trace      # print out all events
```

Inspired by [qira](https://qira.me/).
