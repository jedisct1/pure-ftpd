#ifndef __SIMPLECONF_FTPD_H__
#define __SIMPLECONF_FTPD_H__ 1

#include "simpleconf.h"

static const SimpleConfEntry simpleconf_options[] = {
    {"AllowAnonymousFXP? <bool>",                 "--allowanonymousfxp"},
    {"AllowDotFiles? <bool>",                     "--allowdotfiles"},
    {"AllowUserFXP? <bool>",                      "--allowuserfxp"},
#ifdef WITH_ALTLOG
    {"AltLog (<any*>)",                           "--altlog=$0"},
#endif
#ifdef THROTTLING
    {"AnonymousBandwidth (<digits>) (<digits>)",  "--anonymousbandwidth=$0:$1"},
    {"AnonymousBandwidth (<digits>)",             "--anonymousbandwidth=$0"},
#endif
    {"AnonymousCanCreateDirs? <bool>",            "--anonymouscancreatedirs"},
    {"AnonymousCantUpload? <bool>",               "--anonymouscantupload"},
    {"AnonymousOnly? <bool>",                     "--anonymousonly"},
#ifdef RATIOS
    {"AnonymousRatio (<digits>) (<digits>)",      "--anonymousratio=$0:$1"},
#endif
    {"AntiWarez? <bool>",                         "--antiwarez"},
    {"AutoRename? <bool>",                        "--autorename"},
#ifndef NO_STANDALONE
    {"Bind (<nospace>)",                          "--bind=$0"},
#endif
#ifdef WITH_OSX_BONJOUR
    {"Bonjour (<nospace>)",                       "--bonjour=$0"},
#endif
    {"BrokenClientsCompatibility? <bool>",        "--brokenclientscompatibility"},
#ifdef WITH_TLS
    {"CertFileAndKey (<any>) (<any>)",            "--certfile=$0,$1"},
    {"CertFile (<any*>)",                         "--certfile=$0"},
#endif
    {"ChrootEveryone? <bool>",                    "--chrooteveryone"},
    {"CreateHomeDir? <bool>",                     "--createhomedir"},
    {"CustomerProof? <bool>",                     "--customerproof"},
#ifndef NO_STANDALONE
    {"Daemonize? <bool>",                         "--daemonize"},
#endif
    {"DisplayDotFiles? <bool>",                   "--displaydotfiles"},
    {"DontResolve? <bool>",                       "--dontresolve"},
#ifdef WITH_TLS
    {"ExtCert (<any*>)",                          "--extcert=$0"},
#endif
    {"ForcePassiveIP (<nospace>)",                "--forcepassiveip=$0"},
#ifdef COOKIE
    {"FortunesFile (<any*>)",                     "--fortunesfile=$0"},
#endif
    {"IPV4Only? <bool>",                          "--ipv4only"},
    {"IPV6Only? <bool>",                          "--ipv6only"},
    {"KeepAllFiles? <bool>",                      "--keepallfiles"},
    {"LimitRecursion (<digits>) (<digits>)",      "--limitrecursion=$0:$1"},
#ifdef WITH_EXTAUTH
    {"ExtAuth (<any*>)",                          "--login=extauth:$0"},
#endif
#ifdef WITH_LDAP
    {"LDAPConfigFile (<any*>)",                   "--login=ldap:$0"},
#endif
#ifdef WITH_MYSQL
    {"MySQLConfigFile (<any*>)",                  "--login=mysql:$0"},
#endif
#ifdef USE_PAM
    {"PAMAuthentication? <bool>",                 "--login=pam"},
#endif
#ifdef WITH_PGSQL
    {"PGSQLConfigFile (<any*>)",                  "--login=pgsql:$0"},
#endif
#ifdef WITH_PUREDB
    {"PureDB (<any*>)",                           "--login=puredb:$0"},
#endif
    {"UnixAuthentication? <bool>",                "--login=unix"},
    {"LogPID? <bool>",                            "--logpid"},
    {"MaxClientsNumber (<digits>)",               "--maxclientsnumber=$0"},
#ifndef NO_STANDALONE
    {"MaxClientsPerIP (<digits>)",                "--maxclientsperip=$0"},
#endif
    {"MaxDiskUsage (<digits>)",                   "--maxdiskusagepct=$0"},
    {"MaxIdleTime (<digits>)",                    "--maxidletime=$0"},
    {"MaxLoad (<digits>)",                        "--maxload=$0"},
    {"MinUID (<digits>)",                         "--minuid=$0"},
    {"NATmode? <bool>",                           "--natmode"},
    {"NoAnonymous? <bool>",                       "--noanonymous"},
    {"NoChmod? <bool>",                           "--nochmod"},
    {"NoRename? <bool>",                          "--norename"},
    {"NoTruncate? <bool>",                        "--notruncate"},
    {"PassivePortRange (<digits>) (<digits>)",    "--passiveportrange=$0:$1"},
#ifdef PER_USER_LIMITS
    {"PerUserLimits (<digits>):(<digits>)",       "--peruserlimits=$0:$1"},
#endif
#ifndef NO_STANDALONE
    {"PIDFile (<any*>)",                          "--pidfile=$0"},
#endif
    {"ProhibitDotFilesWrite? <bool>",             "--prohibitdotfileswrite"},
    {"ProhibitDotFilesRead? <bool>",              "--prohibitdotfilesread"},
#ifdef QUOTAS
    {"Quota (<digits>):(<digits>)",               "--quota=$0:$1"},
#endif
    {"SyslogFacility (<alnum>)",                  "--syslogfacility=$0"},
#ifdef WITH_TLS
    {"TLSCipherSuite (<nospace>)",                "--tlsciphersuite=$0"},
    {"TLS (<digits>)",                            "--tls=$0"},
#endif
    {"TrustedGID (<digits>)",                     "--trustedgid=$0"},
#ifdef WITH_VIRTUAL_HOSTS
    {"TrustedIP (<nospace>)",                     "--trustedip=$0"},
#endif
    {"Umask (<digits>):(<digits>)",               "--umask=$0:$1"},
#ifdef WITH_UPLOAD_SCRIPT
    {"CallUploadScript? <bool>",                  "--uploadscript"},
#endif
#ifdef THROTTLING
    {"UserBandwidth (<digits>) (<digits>)",       "--userbandwidth=$0:$1"},
    {"UserBandwidth (<digits>)",                  "--userbandwidth=$0"},
#endif
#ifdef RATIOS
    {"UserRatio (<digits>) (<digits>)",           "--userratio=$0:$1"},
#endif
    {"VerboseLog? <bool>",                        "--verboselog"}
};

#endif
