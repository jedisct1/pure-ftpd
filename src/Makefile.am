noinst_LIBRARIES = libpureftpd.a

sbin_PROGRAMS = \
	pure-authd \
	pure-ftpd \
	pure-ftpwho \
	pure-mrtginfo \
	pure-quotacheck \
	pure-uploadscript

bin_PROGRAMS = \
	pure-statsdecode \
	pure-pw \
	pure-pwconvert

noinst_PROGRAMS = \
	ptracetest

libpureftpd_a_CFLAGS = -DINCLUDE_IO_WRAPPERS=1

libpureftpd_a_DEPENDS = \
	../puredb/src/libpuredb_read.a

libpureftpd_a_SOURCES = \
	altlog.c \
	altlog.h \
	alt_arc4random.c \
	alt_arc4random.h \
	bonjour.h \
	bonjour.c \
	bsd-glob.c \
	bsd-glob.h \
	bsd-realpath.h \
	bsd-realpath.c \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	caps.c \
	caps_p.h \
	caps.h \
	crypto.c \
	crypto.h \
	crypto-md5.c \
	crypto-md5.h \
	crypto-sha1.c \
	crypto-sha1.h \
	daemons.c \
	diraliases.h \
	diraliases.c \
	dynamic.c \
	dynamic.h \
	fakesnprintf.h \
	fakesnprintf.c \
	fakechroot.h \
	fakechroot.c \
	ftp_parser.c \
	ftpd.c \
	ftpd_p.h \
	ftpd.h \
	ftpwho-update.c \
	ftpwho-update.h \
	ftpwho-update_p.h \
	ftpwho-read.h \
	ftpwho-read.c \
	getloadavg.h \
	getloadavg.c \
	globals.h \
	ipstack.c \
	ipstack.h \
	log_unix.c \
	log_unix.h \
	log_mysql.c \
	log_mysql.h \
	log_mysql_p.h \
	log_pgsql.c \
	log_pgsql.h \
	log_pgsql_p.h \
	log_pam.c \
	log_pam.h \
	log_ldap.c \
	log_ldap.h \
	log_ldap_p.h \
	log_puredb.c \
	log_puredb.h \
	log_extauth.c \
	log_extauth.h \
	log_extauth_p.h \
	ls.c \
	ls_p.h \
	messages.h \
	messages_cs_cz.h \
	messages_da.h \
	messages_de.h \
	messages_en.h \
	messages_es.h \
	messages_fr.h \
	messages_fr_funny.h \
	messages_hu.h \
	messages_it.h \
	messages_kr.h \
	messages_nl.h \
	messages_pl.h \
	messages_pt_br.h \
	messages_ro.h \
	messages_sk.h \
	messages_sv.h \
	messages_no.h \
	messages_ru.h \
	messages_tr.h \
	messages_zh_cn.h \
	messages_zh_tw.h \
	mysnprintf.c \
	mysnprintf.h \
	parser.c \
	parser_p.h \
	parser.h \
	privsep.h \
	privsep_p.h \
	privsep.c \
	quotas.h \
	quotas.c \
	safe_rw.h \
	safe_rw.c \
	syslognames.h \
	tls.h \
	tls.c \
	upload-pipe.c \
	upload-pipe.h

pure_ftpd_DEPENDS = \
	libpureftpd.a \
	../puredb/src/libpuredb_read.a

pure_ftpd_LDADD = \
	libpureftpd.a \
	../puredb/src/libpuredb_read.a \
	@LDAP_SSL_LIBS@ @GETLOADAVG_LIBS@ @BONJOUR_LDADD@

pure_ftpd_SOURCES = \
	main.c

pure_mrtginfo_CFLAGS = -DIN_PURE_MRTGINFO=1

pure_mrtginfo_SOURCES = \
	daemons.c \
	fakesnprintf.h \
	fakesnprintf.c \
	messages.h \
	pure-mrtginfo.c \
	mysnprintf.c \
	mysnprintf.h

pure_ftpwho_SOURCES = \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	fakesnprintf.h \
	fakesnprintf.c \
	ftpd.h \
	ftpwho-update.h \
	ipstack.c \
	ipstack.h \
	mysnprintf.c \
	mysnprintf.h \
	pure-ftpwho.c \
	syslognames.h

pure_uploadscript_SOURCES = \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	fakesnprintf.h \
	fakesnprintf.c \
	ftpd.h \
	ftpwho-update.h \
	mysnprintf.c \
	mysnprintf.h \
	pure-uploadscript.c \
	pure-uploadscript_p.h \
	safe_rw.c \
	safe_rw.h \
	syslognames.h

pure_statsdecode_SOURCES = \
	fakesnprintf.h \
	fakesnprintf.c \
	ftpd.h \
	mysnprintf.c \
	mysnprintf.h \
	pure-statsdecode.c

pure_quotacheck_SOURCES = \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	fakesnprintf.h \
	fakesnprintf.c \
	ftpd.h \
	mysnprintf.c \
	mysnprintf.h \
	pure-quotacheck.c \
	safe_rw.c \
	safe_rw.h

pure_pw_DEPENDS = \
	../puredb/src/libpuredb_write.a

pure_pw_LDADD = \
	../puredb/src/libpuredb_write.a

pure_pw_SOURCES = \
	alt_arc4random.c \
	alt_arc4random.h \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	fakesnprintf.h \
	fakesnprintf.c \
	ftpd.h \
	mysnprintf.c \
	mysnprintf.h \
	pure-pw.c \
	pure-pw.h \
	safe_rw.c \
	safe_rw.h

pure_pwconvert_SOURCES = \
	fakesnprintf.h \
	fakesnprintf.c \
	ftpd.h \
	mysnprintf.c \
	mysnprintf.h \
	pure-pwconvert.c

pure_authd_SOURCES = \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	fakesnprintf.h \
	fakesnprintf.c \
	ftpd.h \
	mysnprintf.c \
	mysnprintf.h \
	pure-authd.c \
	pure-authd_p.h \
	safe_rw.c \
	safe_rw.h

ptracetest_SOURCES = \
	ptracetest.c
