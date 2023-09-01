#!/bin/bash
set -ex

apt update
apt install -y git \
               build-essential \
               autoconf \
               automake \
               libtool \
               ninja-build \
               libssl-dev \
               libpcre3-dev \
               wget

NGINX_VERSION=1.17.5
CMAKE_VERSION=3.18
CMAKE_BUILD=3

mkdir -p tmp
cd tmp
ROOT=$(pwd)

# Fetch all the files we need
#wget https://cmake.org/files/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}.${CMAKE_BUILD}-Linux-x86_64.sh
cp /home/zzd/cmake-${CMAKE_VERSION}.${CMAKE_BUILD}-Linux-x86_64.sh .
git clone --single-branch --branch pq-tls-experiment https://github.com/Akutamatsu/liboqs.git
git clone --single-branch --branch pq-tls-experiment https://github.com/Akutamatsu/openssl.git
wget nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && tar -zxvf nginx-${NGINX_VERSION}.tar.gz

# Install the latest CMake
mkdir cmake
sh cmake-${CMAKE_VERSION}.${CMAKE_BUILD}-Linux-x86_64.sh --skip-license --prefix=${ROOT}/cmake

# build liboqs
cd liboqs
mkdir build && cd build
${ROOT}/cmake/bin/cmake -GNinja -DCMAKE_INSTALL_PREFIX=${ROOT}/openssl/oqs ..
ninja && ninja install

