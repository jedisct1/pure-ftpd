sbin_PROGRAMS = \
	pure-ftpd \
	pure-mrtginfo \
	pure-ftpwho \
	pure-uploadscript \
	pure-quotacheck \
	pure-authd

bin_PROGRAMS = \
	pure-statsdecode \
	pure-pw \
	pure-pwconvert

noinst_PROGRAMS = \
	ptracetest

pure_ftpd_LDADD = \
	../puredb/src/libpuredb_read.a \
	@LDAP_SSL_LIBS@ @GETLOADAVG_LIBS@ @BONJOUR_LDADD@

pure_ftpd_CFLAGS = -DINCLUDE_IO_WRAPPERS=1

pure_ftpd_SOURCES = \
	daemons.c \
	ftpd.c \
	ftpd_p.h \
	ftpd.h \
	syslognames.h \
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
	parser.c \
	parser_p.h \
	parser.h \
	globals.h \
	bsd-glob.c \
	bsd-glob.h \
	messages.h \
	fakesnprintf.h \
	fakesnprintf.c \
	bsd-realpath.h \
	bsd-realpath.c \
	mysnprintf.c \
	mysnprintf.h \
	caps.c \
	caps_p.h \
	caps.h \
	ftp_parser.c \
	dynamic.c \
	dynamic.h \
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
	ftpwho-update.c \
	ftpwho-update.h \
	ftpwho-update_p.h \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	upload-pipe.c \
	upload-pipe.h \
	ipstack.c \
	ipstack.h \
	altlog.c \
	altlog.h \
	crypto.c \
	crypto.h \
	crypto-md5.c \
	crypto-md5.h \
	crypto-sha1.c \
	crypto-sha1.h \
	quotas.h \
	quotas.c \
	fakechroot.h \
	fakechroot.c \
	diraliases.h \
	diraliases.c \
	ftpwho-read.h \
	ftpwho-read.c \
	getloadavg.h \
	getloadavg.c \
	privsep.h \
	privsep_p.h \
	privsep.c \
	tls.h \
	tls.c \
	bonjour.h \
	bonjour.c

pure_mrtginfo_CFLAGS = -DIN_PURE_MRTGINFO=1

pure_mrtginfo_SOURCES = \
	daemons.c \
	pure-mrtginfo.c \
	messages.h \
	fakesnprintf.h \
	fakesnprintf.c \
	mysnprintf.c \
	mysnprintf.h

pure_ftpwho_SOURCES = \
	pure-ftpwho.c \
	ftpd.h \
	syslognames.h \
	ftpwho-update.h \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	fakesnprintf.h \
	fakesnprintf.c \
	mysnprintf.c \
	mysnprintf.h \
	ipstack.c \
	ipstack.h

pure_uploadscript_SOURCES = \
	pure-uploadscript.c \
	pure-uploadscript_p.h \
	ftpd.h \
	syslognames.h \
	ftpwho-update.h \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	fakesnprintf.h \
	fakesnprintf.c \
	mysnprintf.c \
	mysnprintf.h

pure_statsdecode_SOURCES = \
	pure-statsdecode.c \
	ftpd.h \
	fakesnprintf.h \
	fakesnprintf.c \
	mysnprintf.c \
	mysnprintf.h

pure_quotacheck_SOURCES = \
	pure-quotacheck.c \
	ftpd.h \
	fakesnprintf.h \
	fakesnprintf.c \
	mysnprintf.c \
	mysnprintf.h \
	bsd-getopt_long.c \
	bsd-getopt_long.h

pure_pw_LDADD = \
	../puredb/src/libpuredb_write.a

pure_pw_SOURCES = \
	pure-pw.c \
	pure-pw.h \
	ftpd.h \
	fakesnprintf.h \
	fakesnprintf.c \
	mysnprintf.c \
	mysnprintf.h \
	bsd-getopt_long.c \
	bsd-getopt_long.h

pure_pwconvert_SOURCES = \
	pure-pwconvert.c \
	ftpd.h \
	fakesnprintf.h \
	fakesnprintf.c \
	mysnprintf.c \
	mysnprintf.h

pure_authd_SOURCES = \
	pure-authd.c \
	pure-authd_p.h \
	ftpd.h \
	bsd-getopt_long.c \
	bsd-getopt_long.h \
	fakesnprintf.h \
	fakesnprintf.c \
	mysnprintf.c \
	mysnprintf.h

ptracetest_SOURCES = \
	ptracetest.c
