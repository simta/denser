ACLOCAL_AMFLAGS = -I m4
pkgconfigdir = $(libdir)/pkgconfig

bin_PROGRAMS = dense
include_HEADERS = denser.h
lib_LTLIBRARIES = libdnsr.la
nodist_pkgconfig_DATA = packaging/pkgconfig/denser.pc

libdnsr_la_SOURCES = argcargv.c argcargv.h bprint.c bprint.h config.c error.c event.c event.h internal.h match.c new.c parse.c query.c result.c timeval.c timeval.h
libdnsr_la_LDFLAGS = -export-symbols libdnsr.sym

dense_SOURCES = dense.c
dense_LDADD = libdnsr.la

EXTRA_DIST = VERSION libdnsr.sym packaging/rpm/denser.spec

rpm: dist-gzip
	rpmbuild -ta $(distdir).tar.gz
