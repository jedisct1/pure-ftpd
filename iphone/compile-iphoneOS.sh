#! /bin/sh

export CPPFLAGS="-D__IPHONE__=1 -DALLOW_DELETION_OF_TEMPORARY_FILES=1 -DNO_PROCNAME_CHANGE -DANON_CAN_CHANGE_PERMS=1 -DANON_CAN_CHANGE_UTIME=1 -DANON_CAN_DELETE=1 -DANON_CAN_RESUME=1 -DANON_CAN_RENAME=1"
export XCODEDIR="/Applications/Xcode.app/Contents/Developer"

for arch in armv7 armv7s; do
(
export BASEDIR="${XCODEDIR}/Platforms/iPhoneOS.platform/Developer"
export PATH="${BASEDIR}/usr/bin:$BASEDIR/usr/sbin:$PATH"
export SDK="${BASEDIR}/SDKs/iPhoneOS6.0.sdk"
export CFLAGS="-pthread -Oz -mthumb -arch ${arch} -isysroot ${SDK}"
export LDFLAGS="-pthread -mthumb -arch ${arch} -isysroot ${SDK}"

rm -fr "obj-$arch" 2>/dev/null
mkdir "obj-$arch" 2>/dev/null
cd "obj-$arch" || exit 1
../../configure --host=arm-apple-darwin10 --with-boring --without-inetd --without-pam --with-nonroot --with-rfc2640 || exit 2
make || make
cd src || exit 1
mv libpureftpd.a "_libpureftpd-$arch.a"
)
done

for arch in i386; do
(
export BASEDIR="${XCODEDIR}/Platforms/iPhoneSimulator.platform/Developer"
export PATH="${BASEDIR}/usr/bin:$BASEDIR/usr/sbin:$PATH"
export SDK="${BASEDIR}/SDKs/iPhoneSimulator6.0.sdk"
export CFLAGS="-pthread -O0 -g3 -mthumb -arch ${arch} -isysroot ${SDK}"
export LDFLAGS="-pthread -g3 -mthumb -arch ${arch} -isysroot ${SDK}"
export CPPFLAGS="${CPPFLAGS} -DDEFAULT_FTP_PORT_S=2121"

rm -fr "obj-$arch" 2>/dev/null
mkdir "obj-$arch" 2>/dev/null
cd "obj-$arch" || exit 1
../../configure --host=arm-apple-darwin10 --with-boring --without-inetd --without-pam --with-nonroot --with-rfc2640 || exit 2
make || make
cd src || exit 1
mv libpureftpd.a "_libpureftpd-$arch.a"
)
done

lipo -create -output libpureftpd.a \
  obj-arm*/src/_libpureftpd-armv*.a \
  obj-i386*/src/_libpureftpd-i386.a || exit 3
  
rm -fr obj-arm* obj-i386

lipo -info libpureftpd.a
