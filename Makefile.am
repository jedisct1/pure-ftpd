    
doc_DATA = \
	FAQ \
	README.LDAP \
	README.MySQL \
	README.PGSQL \
	README.Configuration-File \
	README.Virtual-Users \
	README.Authentication-Modules \
	README.TLS \
	README.MacOS-X \
	pure-ftpd.conf \
	pureftpd.schema \
	pureftpd-ldap.conf \
	pureftpd-mysql.conf \
	pureftpd-pgsql.conf

EXTRA_DIST = \
	FAQ \
	HISTORY \
	Makefile.gui \
	README.Authentication-Modules \
	README.Configuration-File \
	README.Donations \
	README.LDAP \
	README.MacOS-X \
	README.MySQL \
	README.PGSQL \
	README.TLS \
	README.Virtual-Users \
	README.Windows \
	THANKS \
	pure-ftpd.conf \
	pure-ftpd.png \
	pureftpd-ldap.conf \
	pureftpd-mysql.conf \
	pureftpd-pgsql.conf \
	pureftpd.schema

SUBDIRS = \
	puredb \
	src \
	man \
	pam \
	gui \
	m4

install-data-local:
	@$(mkinstalldirs) $(DESTDIR)$(sysconfdir); \
	if [ -f $(DESTDIR)$(sysconfdir)/pure-ftpd.conf ]; then \
		if cmp -s $(srcdir)/pure-ftpd.conf $(docdir)/pure-ftpd.conf; then \
			echo "Configuration file unchanged"; \
		else \
			echo "The example configuration file [$(docdir)/pure-ftpd.conf] has been updated."; \
			echo "You may want to compare it with the one at [$(DESTDIR)$(sysconfdir)/pure-ftpd.conf]."; \
		fi; \
	else \
		$(INSTALL_DATA) $(srcdir)/pure-ftpd.conf $(DESTDIR)$(sysconfdir)/pure-ftpd.conf; \
	fi

uninstall-local:
	@if cmp -s $(srcdir)/pure-ftpd.conf $(DESTDIR)$(sysconfdir)/pure-ftpd.conf; then \
		echo "$(DESTDIR)$(sysconfdir)/pure-ftpd.conf has not changed and will be removed."; \
		rm -f $(DESTDIR)$(sysconfdir)/pure-ftpd.conf; \
		rmdir $(DESTDIR)$(sysconfdir) 2> /dev/null ||:; \
	fi
