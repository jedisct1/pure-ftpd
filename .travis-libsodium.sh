#! /bin/sh

set -e

git clone https://github.com/jedisct1/libsodium.git --branch=stable
cd libsodium
./configure --disable-dependency-tracking --enable-minimal --prefix=/usr
make -j$(nproc)
sudo make install
/sbin/ldconfig ||:
