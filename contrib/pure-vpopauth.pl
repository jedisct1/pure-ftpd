#! /usr/bin/perl -w

# - authentication module for pure-ftpd using vpasswd vpopmail password files.
# - Saturday, 12 May 2002 - released
# - copyright (c) Dan Caescu - daniel@guitar.ro , jamie_fd@yahoo.com
# - vpopmail has to be compiled with clear text passwords in order for 
# - this to work.  
# - also, there would be great if you would run pure-ftpd with chroot flags
# - 17 Nov 2002, added e-mail checking, a hint from Frank Jedi @ pureftpd 
# - I guess it works..? :)  
# - greets to Rox (Roxana Raluca) .

# Change the following settings according to your needs

$VPOPMAIL_PATH = '/usr/local/vpopmail';
$UID = 1000;
$GID = 1000;

# Don't change anything below that line

$AUTHD_ACCOUNT = $ENV{AUTHD_ACCOUNT} or die;
$AUTHD_PASSWORD = $ENV{AUTHD_PASSWORD} or die;

# Checking if AUTHD_ACCOUNT is like user@domain

$AUTHD_ACCOUNT =~ /^[^@]+\@([a-z0-9]+\.)+[a-z]+$/i or die;

# We take care of the user/domain pair 'cause the user comes
# in the user@domain style

@user_domain = split('@', $AUTHD_ACCOUNT);

open (FILE, "$VPOPMAIL_PATH/domains/" . $user_domain[1] . '/vpasswd') or die;

# We take care of the user/pass from vpasswd

while (<FILE>) {
    chomp;
    @date_useri = split ':';
    if ($user_domain[0] eq $date_useri[0] &&
        $AUTHD_PASSWORD eq $date_useri[7]) {
        print "auth_ok:1\n",
              "uid:$UID\n",
              "gid:$GID\n",
              "dir:$date_useri[5]\n",
              "end\n";
        last;
    }    
}

close FILE;
