#! /bin/sh

PATH="/Developer/usr/bin:/Developer/usr/sbin:$PATH"
PLATFORM_PATH="/Developer/Platforms/iPhoneOS.platform"
TARGET_PATH="$PLATFORM_PATH/Developer/SDKs/iPhoneOS3.1.sdk"
CC="$PLATFORM_PATH/Developer/usr/bin/gcc"
CPPFLAGS="-I$TARGET_PATH/usr/include -I$TARGET_PATH/usr/lib/gcc/arm-apple-darwin9/4.2.1/include"
CFLAGS="-arch armv6"
LDFLAGS="-L$TARGET_PATH/usr/lib -arch armv6"
CPP="$PLATFORM_PATH/Developer/usr/bin/cpp"

mkdir obj 2>/dev/null
cd obj || exit 1
../../configure --host=arm-apple-darwin9 --without-pam --with-nonroot || exit 2
make
make



