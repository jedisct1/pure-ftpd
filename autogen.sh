#! /bin/sh

aclocal -I m4 && \
autoheader && \
automake --gnu --add-missing --include-deps && \
autoconf -I m4
