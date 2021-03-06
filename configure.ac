AC_INIT([gromox], [0.17])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux])
AC_PREFIX_DEFAULT([/usr])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.10 foreign subdir-objects])
LT_INIT([disable-static])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX

saved_CPPFLAGS="$CPPFLAGS"
saved_CFLAGS="$CFLAGS"
saved_CXXFLAGS="$CXXFLAGS"
saved_LDFLAGS="$LDFLAGS"
saved_LIBS="$LIBS"

my_CFLAGS="-Wall -Wmissing-declarations -Wwrite-strings"
my_CXXFLAGS="-Wall -Wmissing-declarations"
AC_MSG_CHECKING([available C++ standard])
cxxmode=""
for i in "c++17"; do
	CXXFLAGS="$CXXFLAGS_system -std=$i"
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([])], [cxxmode="$i"])
	AS_IF([test -n "$cxxmode"], [break])
done
CXXFLAGS="$CXXFLAGS_system"
AS_IF([test -n "$cxxmode"], [
	my_CXXFLAGS="$my_CXXFLAGS -std=$cxxmode"
	AC_MSG_RESULT([$cxxmode])
])

AC_ARG_WITH([asan], AS_HELP_STRING([--with-asan], [Activate Address Sanitizer]),
	[
	my_CFLAGS="$my_CFLAGS -fsanitize=address"
	my_CXXFLAGS="$my_CXXFLAGS -fsanitize=address"
	])
dnl fvis is non-conforming and (rightfully) triggers ubsan warnings;
dnl hence we disable fvis as a workaround.
NO_VSYM=""
AC_ARG_WITH([ubsan], AS_HELP_STRING([--with-ubsan], [Activate Undefined Behavior Sanitizer]),
	[
	my_CFLAGS="$my_CFLAGS -fsanitize=undefined"
	my_CXXFLAGS="$my_CXXFLAGS -fsanitize=undefined"
	NO_VSYM=1],
	[
	my_CFLAGS="$my_CFLAGS -fvisibility=hidden"
	my_CXXFLAGS="$my_CXXFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
	])
AC_SUBST([NO_VSYM])


AC_ARG_WITH([unitdir],
	[AS_HELP_STRING([--with-unitdir=PATH], [Path to systemd service unit directory])],
	[unitdir="$withval"],
	[
		unitdir=$("$PKG_CONFIG" systemd --variable systemdsystemunitdir 2>/dev/null)
		AS_IF([test -z "$unitdir"], [unitdir='${prefix}/lib/systemd/system'])
	])
AC_SUBST([unitdir])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([HX], [libHX >= 1.10])
PKG_CHECK_MODULES([crypto], [libcrypto])
PKG_CHECK_MODULES([gumbo], [gumbo])
PKG_CHECK_MODULES([jsoncpp], [jsoncpp >= 1.4.0], [], [
	PKG_CHECK_MODULES([jsoncpp], [jsoncpp >= 0.8 jsoncpp < 1])
])
PKG_CHECK_MODULES([sqlite], [sqlite3])
PKG_CHECK_MODULES([ssl], [libssl])
PKG_CHECK_MODULES([zlib], [zlib])
have_pamheader=""
AC_CHECK_HEADERS([security/pam_modules.h], [have_pamheader="yes"])
AM_CONDITIONAL([HAVE_PAM], [test "$have_pamheader" = yes])
AC_DEFUN([MYSQL_WITH_MYSQL_CONFIG],[
	AC_PATH_PROGS([MYSQL_CONFIG], [mysql_config mariadb_config])
	AC_ARG_WITH([mysql-config], AS_HELP_STRING([--with-mysql-config=PATH], [path to the mysql-config script of mysql]),
		[MYSQL_CONFIG="$withval"])
	AS_IF([test -z "$MYSQL_CONFIG"], [AC_MSG_ERROR([mysql config program not found])])
	mysql_CFLAGS=$($MYSQL_CONFIG --include)
	mysql_LIBS=$($MYSQL_CONFIG --libs)
	mysql_VERSION=$($MYSQL_CONFIG --version) # see if it's there

	if test -z "$mysql_VERSION"; then
		AC_MSG_ERROR([Cannot find a mysql installation. Please use --with-mysql-config=PATH or install libmysqlclient-dev.])
	fi

	AC_SUBST([mysql_CFLAGS])
	AC_SUBST([mysql_LIBS])
	AC_SUBST([mysql_VERSION])
	AC_MSG_CHECKING([for MySQL includes])
	AC_MSG_RESULT([$mysql_CFLAGS])
	AC_MSG_CHECKING([for MySQL libs])
	AC_MSG_RESULT([$mysql_LIBS])
])
MYSQL_WITH_MYSQL_CONFIG
AC_ARG_WITH([php], [AS_HELP_STRING([--without-php], [Disable building PHP components])])
AS_IF([test "$with_php" != "no"], [
	PHP_WITH_PHP_CONFIG
	CPPFLAGS="$saved_CPPFLAGS"
	CFLAGS="$saved_CFLAGS"
	CXXFLAGS="$saved_CXXFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
])
AM_CONDITIONAL([HAVE_PHP], [test "$with_php" != no])

AC_SUBST([my_CFLAGS])
AC_SUBST([my_CXXFLAGS])
AH_TEMPLATE([PROJECT_VERSION], [])
AC_DEFINE([PROJECT_VERSION], [PACKAGE_VERSION]) dnl for now
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
