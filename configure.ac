# Process this file with autoconf to produce a configure script.
AC_INIT(denser, m4_esyscmd([bash version.sh]), denser@umich.edu)
AM_INIT_AUTOMAKE([foreign])
AC_PREREQ(2.52)
AC_COPYRIGHT([Copyright (c) 2003-2015 Regents of The University of Michigan. All Rights Reserved.])
AC_CONFIG_SRCDIR([dense.c])
AC_CONFIG_MACRO_DIR([m4])

LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Check host
AC_C_BIGENDIAN( ENDIAN="-DENDIAN_BIG", ENDIAN="-DENDIAN_LITTLE" )
AC_SUBST(ENDIAN)

# Miscellaneous:
if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes"}
fi
AC_SUBST(OPTOPTS)

AC_ARG_WITH(resolvconf, AC_HELP_STRING([--with-resolvconf=PATH], [default resolv.conf path]), [], with_resolvconf="/etc/resolv.conf")
AC_DEFINE_UNQUOTED(_DNSR_RESOLV_CONF_PATH, ["$with_resolvconf"], [default resolv.conf path])

# Checks for libraries.
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
