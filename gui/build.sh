#! /bin/sh
# Please have a TMP or TMPDIR environment variable if you don't trust /tmp.

export PATH=/usr/local/bin:/usr/local/sbin:$PATH

if [ -z "$dialog" ] ; then
  if [ -n "$DISPLAY" ] ; then
    Xdialog --msgbox 'Welcome to the Pure-FTPd configuration tool' 8 60 2> /dev/null && dialog='Xdialog'
    gauge='--gauge'
  fi
fi  
if [ -z "$dialog" ] ; then
  dialog --msgbox 'Welcome to the Pure-FTPd configuration tool' 8 60 2> /dev/null && dialog='dialog'

# Workaround for old versions of 'dialog' (Slackware)

  if "$dialog" 2>&1 | grep gauge > /dev/null ; then
    gauge='--gauge'
  elif "$dialog" 2>&1 | grep guage > /dev/null ; then
    gauge='--guage'
  else
    gauge=''
  fi    
fi  
if [ -z "$dialog" ] ; then
  lxdialog --msgbox 'Welcome to the Pure-FTPd configuration tool' 8 60 2> /dev/null && dialog='lxdialog'
fi  
if [ -z "$dialog" ] ; then
  /usr/src/linux/scripts/lxdialog/lxdialog --msgbox 'Welcome to the Pure-FTPd configuration tool' 8 60 2> /dev/null && dialog='/usr/src/linux/scripts/lxdialog/lxdialog'
fi  

if [ -z "$dialog" ] ; then
  echo "No 'dialog' found, GUI installation impossible"
  exit 1
fi  

# Find a writable temporary directory
tempdir=''
for tmpdir in "$TMP" "$TMPDIR" /tmp /var/tmp; do
  if [ -z "$tempdir" ] && [ -d "$tmpdir" ] && [ -w "$tmpdir" ]; then
    tempdir="$tmpdir"
  fi
done
if [ -z "$tempdir" ]; then
  echo 'Unable to find a suitable temporary directory'
  exit 1
fi

# Create a temporary file
tmp=`mktemp $tempdir/build.gui.XXXXXX` || exit 1
trap "rm -f $tmp; exit 1" 1 2 11 15

$dialog \
--title 'Compile-time options' \
--separate-output \
--checklist 'Defaults should be fine for most users' \
20 78 10 \
'without-standalone' "Don't compile the standalone server code" off \
'without-inetd' "Don't support super-servers (like inetd)" off \
'without-capabilities' "Don't use Linux capabilities (default=detect)" off \
'without-shadow' "Don't use shadow passwords (default=detect)" off \
'without-usernames' "Use only numerical UIDs/GIDs" off \
'without-iplogging' "Never log remote IP addresses (confidentiality)" off \
'without-humor' "Disable humor (enabled by default)" off \
'without-ascii' "Don't support 7-bits (ASCII) transfers" off \
'without-banner' "Don't display the nice initial banner" off \
'without-nonalnum' "Only allow minimal alpha-numeric characters" off \
'without-unicode' "Disable utf8 non-latin characters" off \
'without-globbing' "Don't include the globbing code" off \
'without-sendfile' "Don't use zero-copy optimizations" off \
'without-cork' "Don't use TCP_CORK optimizations" off \
'with-brokenrealpath' "If your C library has a broken realpath()" off \
'with-probe-random-dev' "To check for /dev/*random at run-time" off \
'with-minimal' "Build only a minimal server for embedded systems" off \
'with-paranoidmsg' "Use paranoid, but not admin-friendly messages" off \
'with-sysquotas' "Use system (not virtual) quotas" off \
'with-ldap' "Users database is an LDAP directory" off \
'with-mysql' "Users database is a MySQL database" off \
'with-altlog' "Support alternative log format (Apache-like)" on \
'with-pam' 'Enable PAM authentication' off \
'with-puredb' 'Support virtual (FTP-only) users' on \
'with-extauth' 'Support external authentication modules' on \
'with-cookie' "Support 'fortune' cookies" on \
'with-throttling' "Support bandwidth throttling" on \
'with-ftpwho' "Support the pure-ftpwho command" on \
'with-ratios' "Support upload/download ratios" on \
'with-quotas' "Support .ftpquota files" on \
'with-welcomemsg' "welcome.msg files backward compatibility" off \
'with-uploadscript' "Allow running scripts after upload (experimental)" on \
'with-virtualhosts' "Allow a distinct content for each IP address" on \
'with-virtualchroot' "Follow symlinks outside a chroot jail" off \
'with-diraliases' "Support directory aliases" on \
'with-peruserlimits' "Support per-user concurrency limits" on \
'with-privsep' "Enable privilege separation" on \
'with-tls' "Support SSL/TLS security layer (experimental)" off \
'with-rfc2640' "Support for UTF-8 encoding for file names" off \
'with-bonjour' "Support Bonjour on MacOS X" off \
2> $tmp

cfgline='';
for z in $(cat $tmp) ; do
  cfgline="$cfgline --$z"
done  

$dialog \
--title 'Compile-time options' \
--radiolist 'Choose a language for server messages' \
20 78 10 \
'english' "This is the default" on \
'german' "Contributed by Mathias Gumz" off \
'romanian' "Contributed by Claudiu Costin" off \
'french' "Contributed by Ping" off \
'french-funny' "Silly french messages" off \
'polish' "Contributed by Arkadiusz Miskiewicz" off \
'spanish' "Contributed by Luis Llorente Campo" off \
'danish' "Contributed by Isak Lyberth" off \
'dutch' "Contributed by Johan Huisman" off \
'italian' "Contributed by Stefano F." off \
'brazilian-portuguese' "Contributed by Roger C. Demetrescu" off \
'slovak' "Contributed by Robert Varga" off \
'korean' "Contributed by Im Eunjea" off \
'swedish' "Contributed by Ulrik Sartipy" off \
'norwegian' "Contributed by Kurt Inge Smadal" off \
'russian' "Contributed by Andrey Ulanov" off \
'traditional-chinese' "Contributed by Hether Fygul" off \
'simplified-chinese' "Contributed by Hether Fygul" off \
'czech' "Contributed by Martin Sarfy" off \
'turkish' "Contributed by Mehmet Cokcevik" off \
'hungarian' "Contributed by Banhalmi Csaba" off \
'catalan' "Contributed by Oriol Magrano" off \
2> $tmp

z=$(cat $tmp)
cfgline="$cfgline --with-language=$z"

$dialog \
--title 'Compile-time options' \
--inputbox 'Installation prefix (/usr/local is not a bad idea)' \
10 78 \
'/usr/local' \
2> $tmp

prefix=$(cat $tmp)
rm -f "$tmp" 2>/dev/null >&2
if [ -n "$prefix" ] ; then
  cfgline="$cfgline --prefix=$prefix"
else
  prefix='/usr/local'
fi

if [ ! -f "configure" ] ; then
  cd ..
  if [ ! -f "configure" ] ; then
    echo 'Setup problem... try to install manually'
    exit 1
  fi
fi

if [ -n "$gauge" ] ; then
(
  echo "./configure $cfgline" > build.gui.log
  echo 20
  rm -f config.cache 2>/dev/null >&2
  echo 30
  ./configure $cfgline >&2 >> build.gui.log
  echo 50
  make clean >&2 >> build.gui.log
  echo 60
  make >&2 >> build.gui.log
  echo 80
  make install-strip >&2 >> build.gui.log
  export instfailure
  echo 100
) | $dialog \
  --title 'Compilation and installation' \
  "$gauge" 'Please wait...' 10 78 10
else
  echo "./configure $cfgline" > build.gui.log
  rm -f config.cache 2>/dev/null >&2
  ./configure $cfgline >&2 >> build.gui.log
  make clean >&2 >> build.gui.log
  make >&2 >> build.gui.log
  make install-strip >&2 >> build.gui.log
  export instfailure
fi

touch "$prefix/pure-ftpd" 2> /dev/null || instfailure="yes"
if [ -z "$instfailure" ] ; then
  $dialog --msgbox \
  "Congratulation, the server is now installed on your system.\nPlease read the documentation to know how to run it." \
  10 78
else
  $dialog --msgbox \
  "Compilation was successful, but you need to be root in\norder to install the files to the selected prefix.\nPlease run 'make install' as root." \
  10 78
fi
