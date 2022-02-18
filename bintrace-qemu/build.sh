#!/bin/bash -ex
QEMU_DIR=qemu
PATCH_DIR=$PWD/qemu-patches
PLUGIN_DIR=$PWD/qemu-plugin
DIST_DIR=$PWD/bintrace-qemu/bin
TAG="v6.1.0"

if [ ! -d $QEMU_DIR ]; then
	echo "[*] Cloning QEMU"
	git clone --branch $TAG --depth=1 https://github.com/qemu/qemu.git $QEMU_DIR

	pushd $QEMU_DIR

	git reset --hard $TAG

	echo "[*] Applying patches"
	EMAIL=$(whoami)@localhost git am $PATCH_DIR/*.patch

	echo "[*] Configuring QEMU..."
	./configure --target-list=x86_64-linux-user --enable-plugins

	popd
fi

echo "[*] Building QEMU..."
pushd $QEMU_DIR
make -j$(nproc) qemu-x86_64
popd

echo "[*] Building tracer plugin"
make -C $PLUGIN_DIR

mkdir -p $DIST_DIR
cp $QEMU_DIR/build/qemu-x86_64 $DIST_DIR/bintrace-qemu-x86_64
cp $PLUGIN_DIR/libtrace.so     $DIST_DIR
