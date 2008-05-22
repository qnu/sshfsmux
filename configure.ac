AC_PREREQ(2.61)
AC_INIT(sshfs-mux, 1.1, sshfsm@gmail.com)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AM_PROG_CC_C_O
CFLAGS="$CFLAGS -Wall -W"
LIBS=
AC_SEARCH_LIBS(dlsym, [dl])
sshnodelay_libs=$LIBS
AC_SUBST(sshnodelay_libs)
LIBS=

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdint.h \
stdlib.h string.h sys/socket.h sys/time.h unistd.h malloc.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_HEADER_TIME
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_UTIME_NULL
AC_CHECK_FUNCS([dup2 ftruncate getpagesize gettimeofday \
memmove memset mkdir munmap realpath rmdir setenv socket \
strchr strdup strerror strncasecmp strrchr uname utime])

# Checking sshnodelay
AC_ARG_ENABLE(sshnodelay,
	[  --disable-sshnodelay    Don't compile NODELAY workaround for ssh])

if test -z "$enable_sshnodelay"; then
	AC_MSG_CHECKING([OpenSSH version])
	[eval `ssh -V 2>&1 | sed -n 's/^OpenSSH_\([1-9][0-9]*\)\.\([0-9][0-9]*\).*/ssh_major=\1 ssh_minor=\2/p'`]
	if test "x$ssh_major" != x -a "x$ssh_minor" != x; then
		if test $ssh_major -gt 4 -o \( $ssh_major = 4 -a $ssh_minor -ge 4 \); then
			AC_MSG_RESULT([$ssh_major.$ssh_minor >= 4.4, disabling NODELAY workaround])
			enable_sshnodelay=no
		else
			AC_MSG_RESULT([$ssh_major.$ssh_minor < 4.4, enabling NODELAY workaround])
			enable_sshnodelay=yes
		fi
	else
		AC_MSG_RESULT([not found])
	fi
fi

if test "$enable_sshnodelay" = "yes"; then
	AC_DEFINE(SSH_NODELAY_WORKAROUND, 1, [Compile ssh NODELAY workaround])
fi
AM_CONDITIONAL(SSH_NODELAY_SO, test "$enable_sshnodelay" = "yes")

# Checking HPN-SSH
AC_ARG_ENABLE(hpnssh,
	[  --enable-hpnssh         Compile with support for HPN-SSH])
if test -z "$enable_hpnssh"; then
	AC_MSG_CHECKING([HPN-SSH])
	[eval `ssh -V 2>&1 | sed -n 's/^OpenSSH_[.p0-9]*-\([hpn]*\)\([0-9][1-9]*\)v\([0-9]*\).*/hpn=\1 hpn_major=\2 hpn_minor=\3/p'`]
	if test "x$hpn" != x -a "x$hpn_major" != x -a "x$hpn_minor" != x; then
		AC_MSG_RESULT([$hpn$hpn_major.$hpn_minor, enabling HPN-SSH support])
		enable_hpnssh=yes
	else
		AC_MSG_RESULT([not found])
		enable_hpnssh=no
	fi
fi
if test "$enable_hpnssh" = "yes"; then
	AC_DEFINE(USE_HPN_SSH, 1, [Compile with support for HPN-SSH])
fi
AM_CONDITIONAL(HPN_SSH, test "$enable_hpnssh" = "yes")

# Checking FUSE and Glib
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
PKG_CHECK_MODULES(SSHFSM, [fuse >= 2.2 glib-2.0 gthread-2.0])
have_fuse_opt_parse=no
oldlibs="$LIBS"
LIBS="$LIBS $SSHFSM_LIBS"
AC_CHECK_FUNC([fuse_opt_parse], [have_fuse_opt_parse=yes])
LIBS="$oldlibs"
if test "$have_fuse_opt_parse" = no; then
	CFLAGS="$CFLAGS -Icompat"
fi
AM_CONDITIONAL(FUSE_OPT_COMPAT, test "$have_fuse_opt_parse" = no)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
