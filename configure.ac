# Process this file with autoconf to produce a configure script.
AC_INIT(denser, m4_esyscmd([sh version.sh]), simta@umich.edu)
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-xz])
AC_PREREQ(2.52)
AC_COPYRIGHT([Copyright (c) 2003-2015 Regents of The University of Michigan])
AC_CONFIG_SRCDIR([dense.c])
AC_CONFIG_MACRO_DIR([m4])

LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Check host
AC_C_BIGENDIAN( ENDIAN="-DENDIAN_BIG", ENDIAN="-DENDIAN_LITTLE" )
AC_SUBST(ENDIAN)

# Checks for functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC

# Local configuration defaults
AC_ARG_WITH(resolvconf, AC_HELP_STRING([--with-resolvconf=PATH], [default resolv.conf path]), [], with_resolvconf="/etc/resolv.conf")
AC_DEFINE_UNQUOTED(DNSR_RESOLV_CONF_PATH, ["$with_resolvconf"], [default resolv.conf path])

# Checks for libraries.
AC_CHECK_LIB([nsl], [inet_ntop])
AC_CHECK_LIB([socket], [socket])

AC_CONFIG_FILES(Makefile packaging/pkgconfig/denser.pc packaging/rpm/denser.spec)
AC_OUTPUT
