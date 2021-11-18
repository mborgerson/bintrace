#!/bin/bash -ex
QEMU_DIR=qemu
PATCH_DIR=$PWD/qemu-patches
TAG="v6.1.0"

pushd $QEMU_DIR
rm $PATCH_DIR/*.patch
git format-patch -o $PATCH_DIR $TAG..HEAD
popd
