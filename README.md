bintrace
========

* Tools to collect and analyze execution traces.
  * Plugin (and patches) to get execution traces from QEMU.
  * Python library to work with those traces.
  * Only intended to be run on Linux, for now. API likely to change.

```bash
sudo apt install capnproto libcapnp-dev ninja-build
git clone https://github.com/mborgerson/bintrace
pip install .
pip install ./bintrace-qemu
bintrace-qemu /usr/bin/uname -a    # produces binary.trace in current dir
python -m bintrace uname.trace     # print out all events
```

Inspired by [qira](https://qira.me/).
