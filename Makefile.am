ACLOCAL_AMFLAGS = -I m4
lib_LTLIBRARIES = libdnsr.la
libdnsr_la_SOURCES = argcargv.c argcargv.h bprint.c bprint.h config.c error.c event.c event.h internal.h match.c new.c parse.c query.c result.c timeval.c timeval.h
include_HEADERS = denser.h
bin_PROGRAMS = dense
dense_SOURCES = dense.c
dense_LDADD = libdnsr.la
EXTRA_DIST = VERSION
