FROM ubuntu:22.04

RUN DEBIAN_FRONTEND=noninteractive \
	apt-get update \
 && apt-get install -qy \
		build-essential \
		git \
		flatbuffers-compiler \
		libflatbuffers-dev \
		libglib2.0-dev \
		ninja-build \
		pkg-config \
		python-is-python3 \
		python3-pip \
		python3-venv

RUN pip install 'https://github.com/mborgerson/bintrace/archive/refs/heads/master.zip'
RUN pip install --no-build-isolation 'https://github.com/mborgerson/bintrace/archive/refs/heads/master.zip#subdirectory=bintrace-qemu'
