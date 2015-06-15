AC_INIT(ckpool, 0.8.8, kernel@kolivas.org)

AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/ckpool.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_USE_SYSTEM_EXTENSIONS

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
# gl_EARLY - maybe later
AC_PROG_GCC_TRADITIONAL
AM_PROG_CC_C_O
LT_INIT([disable-shared])

# gl_INIT - maybe later

dnl Checks for header files.
AC_HEADER_STDC

AC_FUNC_ALLOCA

PKG_PROG_PKG_CONFIG()

AC_CHECK_HEADERS(stdio.h stdlib.h fcntl.h sys/time.h unistd.h dirent.h)
AC_CHECK_HEADERS(ctype.h errno.h byteswap.h string.h time.h fenv.h)
AC_CHECK_HEADERS(endian.h sys/endian.h arpa/inet.h sys/poll.h syslog.h)
AC_CHECK_HEADERS(alloca.h pthread.h stdio.h math.h signal.h sys/prctl.h)
AC_CHECK_HEADERS(sys/types.h sys/socket.h sys/stat.h linux/un.h netdb.h)
AC_CHECK_HEADERS(stdint.h netinet/in.h netinet/tcp.h sys/ioctl.h getopt.h)
AC_CHECK_HEADERS(sys/epoll.h libpq-fe.h postgresql/libpq-fe.h grp.h)
AC_CHECK_HEADERS(gsl/gsl_math.h gsl/gsl_cdf.h)

PTHREAD_LIBS="-lpthread"
MATH_LIBS="-lm"
RT_LIBS="-lrt"

AC_CONFIG_SUBDIRS([src/jansson-2.6])
JANSSON_LIBS="jansson-2.6/src/.libs/libjansson.a"

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(MATH_LIBS)
AC_SUBST(RT_LIBS)
AC_SUBST(JANSSON_LIBS)

AC_ARG_WITH([ckdb],
	[AC_HELP_STRING([--without-ckdb],[Compile ckpool without postgresql database support (default enabled)])],
	[ckdb=$withval]
	)

if test "x$ckdb" != "xno"; then
	AC_CHECK_LIB([pq], [main],[PQ=-lpq],echo "Error: Required library libpq-dev
		not found. Install it or disable postgresql support with --without-ckdb" && exit 1)
	AC_CHECK_LIB([gsl], [main],[GSL=-lgsl],echo "Error: Required library gsl-dev
		not found. Install it or disable support with --without-ckdb" && exit 1)
	AC_CHECK_LIB([gslcblas], [main],[GSLCBLAS=-lgslcblas],echo "Error: Required library gslcblas
		not found. Install it or disable support with --without-ckdb" && exit 1)
	AC_DEFINE([USE_CKDB], [1], [Defined to 1 if ckdb support required])
	PQ_LIBS="-lpq -lgsl -lgslcblas"
else
	PQ_LIBS=""
fi
AM_CONDITIONAL([WANT_CKDB], [test "x$ckdb" != "xno"])
AC_SUBST(PQ_LIBS)

AC_OUTPUT([Makefile] [src/Makefile])

echo
echo "Compilation............: make (or gmake)"
echo "  CPPFLAGS.............: $CPPFLAGS"
echo "  CFLAGS...............: $CFLAGS"
echo "  LDFLAGS..............: $LDFLAGS"
echo "  LDADD................: $PTHREAD_LIBS $MATH_LIBS $RT_LIBS $JANSSON_LIBS"
echo "  db LDADD.............: $PQ_LIBS"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo
