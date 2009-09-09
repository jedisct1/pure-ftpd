
noinst_LIBRARIES = libpuredb_read.a libpuredb_write.a

noinst_HEADERS = puredb_read.h puredb_write.h

noinst_PROGRAMS = example_read example_write regression

libpuredb_read_a_SOURCES = puredb_read.c puredb_read.h puredb_p.h

libpuredb_write_a_SOURCES = puredb_write.c puredb_write.h puredb_p.h

example_read_LDADD = libpuredb_read.a

example_write_LDADD = libpuredb_write.a

regression_LDADD = libpuredb_read.a libpuredb_write.a

example_read_SOURCES = example_read.c puredb_read.h

example_write_SOURCES = example_write.c puredb_write.h

regression_SOURCES = regression.c puredb_read.h puredb_write.h puredb_p.h

