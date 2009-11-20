#! /bin/sh

for arch in armv6 armv7; do
(
export PATH="/Developer/usr/bin:/Developer/usr/sbin:$PATH"
export PLATFORM_PATH="/Developer/Platforms/iPhoneOS.platform"
export TARGET_PATH="$PLATFORM_PATH/Developer/SDKs/iPhoneOS3.1.sdk"
export CC="$PLATFORM_PATH/Developer/usr/bin/gcc"
export CPPFLAGS="-D__IPHONE__=1 -DALLOW_DELETION_OF_TEMPORARY_FILES=1 -DNO_PROCNAME_CHANGE -DANON_CAN_CHANGE_PERMS=1 -DANON_CAN_CHANGE_UTIME=1 -DANON_CAN_DELETE=1 -DANON_CAN_RESUME=1 -DANON_CAN_RENAME=1 -I$TARGET_PATH/usr/include -I$TARGET_PATH/usr/lib/gcc/arm-apple-darwin9/4.2.1/include"
export CFLAGS="-pthread -Oz -arch $arch"
export LDFLAGS="-pthread -L$TARGET_PATH/usr/lib -arch $arch"
export CPP="$PLATFORM_PATH/Developer/usr/bin/cpp"

rm -fr "obj-$arch" 2>/dev/null
mkdir "obj-$arch" 2>/dev/null
cd "obj-$arch" || exit 1
../../configure --host=arm-apple-darwin9 --with-boring --without-inetd --without-pam --with-nonroot --with-rfc2640 || exit 2
make || make
cd src || exit 1
mv libpureftpd.a "_libpureftpd-$arch.a"
)
done

for arch in i386 x86_64; do
(
export CPPFLAGS="-D__IPHONE__=1 -DALLOW_DELETION_OF_TEMPORARY_FILES=1 -DNO_PROCNAME_CHANGE -DANON_CAN_CHANGE_PERMS=1 -DANON_CAN_CHANGE_UTIME=1 -DANON_CAN_DELETE=1 -DANON_CAN_RESUME=1 -DANON_CAN_RENAME=1"
export CFLAGS="-pthread -Os -arch $arch -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5"
export LDFLAGS="-pthread -arch $arch -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5"

rm -fr "obj-$arch" 2>/dev/null
mkdir "obj-$arch" 2>/dev/null
cd "obj-$arch" || exit 1
../../configure --with-boring --without-inetd --without-pam --with-nonroot --with-rfc2640 || exit 2
make || make
cd src || exit 1
mv libpureftpd.a "_libpureftpd-$arch.a"
)
done

lipo -create -output libpureftpd.a \
  obj-arm*/src/_libpureftpd-armv*.a \
  obj-i386/src/_libpureftpd-i386.a \
  obj-x86_64/src/_libpureftpd-x86_64.a || exit 3
  
rm -fr obj-arm* obj-i386 obj-x86_64

lipo -info libpureftpd.a

