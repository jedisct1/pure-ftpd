#ifndef __SIMPLECONF_FTPD_H__
#define __SIMPLECONF_FTPD_H__ 1

#include "simpleconf.h"

static const SimpleConfEntry simpleconf_options[] = {
    {"AllowAnonymousFXP? <bool>",                 "--allowanonymousfxp"},
    {"AllowDotFiles? <bool>",                     "--allowdotfiles"},
    {"AllowUserFXP? <bool>",                      "--allowuserfxp"},
    {"AltLog (<any*>)",                           "--altlog=$0"},
    {"AnonymousBandwidth (<digits>) (<digits>)",  "--anonymousbandwidth=$0:$1"},
    {"AnonymousBandwidth (<digits>)",             "--anonymousbandwidth=$0"},
    {"AnonymousCanCreateDirs? <bool>",            "--anonymouscancreatedirs"},
    {"AnonymousCantUpload? <bool>",               "--anonymouscantupload"},
    {"AnonymousOnly? <bool>",                     "--anonymousonly"},
    {"AnonymousRatio (<digits>) (<digits>)",      "--anonymousratio=$0:$1"},
    {"AntiWarez? <bool>",                         "--antiwarez"},
    {"AutoRename? <bool>",                        "--autorename"},
    {"Bind (<nospace>)",                          "--bind=$0"},
    {"BrokenClientsCompatibility? <bool>",        "--brokenclientscompatibility"},
    {"CertFile (<any*>)",                         "--certfile=$0"},
    {"SNIHandler (<any*>)",                       "--sni-handler=$0"},
    {"ChrootEveryone? <bool>",                    "--chrooteveryone"},
    {"ClientCharset (<nospace>)",                 "--clientcharset=$0"},
    {"CreateHomeDir? <bool>",                     "--createhomedir"},
    {"CustomerProof? <bool>",                     "--customerproof"},
    {"Daemonize? <bool>",                         "--daemonize"},
    {"DisplayDotFiles? <bool>",                   "--displaydotfiles"},
    {"DontResolve? <bool>",                       "--dontresolve"},
    {"ForcePassiveIP (<nospace>)",                "--forcepassiveip=$0"},
    {"FortunesFile (<any*>)",                     "--fortunesfile=$0"},
    {"FileSystemCharset (<nospace>)",             "--fscharset=$0"},
    {"IPV4Only? <bool>",                          "--ipv4only"},
    {"IPV6Only? <bool>",                          "--ipv6only"},
    {"KeepAllFiles? <bool>",                      "--keepallfiles"},
    {"LimitRecursion (<digits>) (<digits>)",      "--limitrecursion=$0:$1"},
    {"ExtAuth (<any*>)",                          "--login=extauth:$0"},
    {"LDAPConfigFile (<any*>)",                   "--login=ldap:$0"},
    {"MySQLConfigFile (<any*>)",                  "--login=mysql:$0"},
    {"PAMAuthentication? <bool>",                 "--login=pam"},
    {"PGSQLConfigFile (<any*>)",                  "--login=pgsql:$0"},
    {"PureDB (<any*>)",                           "--login=puredb:$0"},
    {"UnixAuthentication? <bool>",                "--login=unix"},
    {"LogPID? <bool>",                            "--logpid"},
    {"MaxClientsNumber (<digits>)",               "--maxclientsnumber=$0"},
    {"MaxClientsPerIP (<digits>)",                "--maxclientsperip=$0"},
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
    {"PerUserLimits (<digits>):(<digits>)",       "--peruserlimits=$0:$1"},
    {"PIDFile (<any*>)",                          "--pidfile=$0"},
    {"ProhibitDotFilesWrite? <bool>",             "--prohibitdotfileswrite"},
    {"ProhibitDotFilesRead? <bool>",              "--prohibitdotfilesread"},
    {"Quota (<digits>):(<digits>)",               "--quota=$0:$1"},
    {"SyslogFacility (<alnum>)",                  "--syslogfacility=$0"},
    {"TLSCipherSuite (<nospace>)",                "--tlsciphersuite=$0"},
    {"TLS (<digits>)",                            "--tls=$0"},
    {"TrustedGID (<digits>)",                     "--trustedgid=$0"},
    {"TrustedIP (<nospace>)",                     "--trustedip=$0"},
    {"Umask (<digits>):(<digits>)",               "--umask=$0:$1"},
    {"CallUploadScript? <bool>",                  "--uploadscript"},
    {"UserBandwidth (<digits>) (<digits>)",       "--userbandwidth=$0:$1"},
    {"UserBandwidth (<digits>)",                  "--userbandwidth=$0"},
    {"UserRatio (<digits>) (<digits>)",           "--userratio=$0:$1"},
    {"VerboseLog? <bool>",                        "--verboselog"}
};

#endif
