#! /bin/sh

(
export PATH="/Developer/usr/bin:/Developer/usr/sbin:$PATH"
export PLATFORM_PATH="/Developer/Platforms/iPhoneOS.platform"
export TARGET_PATH="$PLATFORM_PATH/Developer/SDKs/iPhoneOS3.1.sdk"
export CC="$PLATFORM_PATH/Developer/usr/bin/gcc"
export CPPFLAGS="-D__IPHONE__=1 -DNO_PROCNAME_CHANGE -DANON_CAN_CHANGE_PERMS=1 -DANON_CAN_CHANGE_UTIME=1 -DANON_CAN_DELETE=1 -DANON_CAN_RESUME=1 -DANON_CAN_RENAME=1 -I$TARGET_PATH/usr/include -I$TARGET_PATH/usr/lib/gcc/arm-apple-darwin9/4.2.1/include"
export CFLAGS="-Oz -arch armv5 -arch armv6 -arch armv7"
export LDFLAGS="-L$TARGET_PATH/usr/lib -arch armv5 -arch armv6 -arch armv7"
export CPP="$PLATFORM_PATH/Developer/usr/bin/cpp"

rm -fr obj-arm 2>/dev/null
mkdir obj-arm 2>/dev/null
cd obj-arm || exit 1
../../configure --host=arm-apple-darwin9 --without-inetd --without-pam --with-nonroot || exit 2
make || make
cd src || exit 1
mv libpureftpd.a _libpureftpd-armv6.a
)

(
export CPPFLAGS="-D__IPHONE__=1 -DNO_PROCNAME_CHANGE -DANON_CAN_CHANGE_PERMS=1 -DANON_CAN_CHANGE_UTIME=1 -DANON_CAN_DELETE=1 -DANON_CAN_RESUME=1 -DANON_CAN_RENAME=1"
export CFLAGS="-Os -arch i386 -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5"
export LDFLAGS="-arch i386 -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5"

rm -fr obj-i386 2>/dev/null
mkdir obj-i386 2>/dev/null
cd obj-i386 || exit 1
../../configure --without-inetd --without-pam --with-nonroot || exit 2
make || make
cd src || exit 1
mv libpureftpd.a _libpureftpd-i386.a
)

(
export CPPFLAGS="-D__IPHONE__=1 -DNO_PROCNAME_CHANGE -DANON_CAN_CHANGE_PERMS=1 -DANON_CAN_CHANGE_UTIME=1 -DANON_CAN_DELETE=1 -DANON_CAN_RESUME=1 -DANON_CAN_RENAME=1"
export CFLAGS="-Os -arch x86_64 -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5"
export LDFLAGS="-arch x86_64 -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5"

rm -fr obj-x86_64 2>/dev/null
mkdir obj-x86_64 2>/dev/null
cd obj-x86_64 || exit 1
../../configure --without-inetd --without-pam --with-nonroot || exit 2
make || make
cd src || exit 1
mv libpureftpd.a _libpureftpd-x86_64.a
)

lipo -create -output libpureftpd.a \
  obj-arm/src/_libpureftpd-armv6.a \
  obj-i386/src/_libpureftpd-i386.a \
  obj-x86_64/src/_libpureftpd-x86_64.a || exit 3
  
rm -fr obj-arm obj-i386 obj-x86_64

lipo -info libpureftpd.a

