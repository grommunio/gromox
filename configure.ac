AC_INIT([gromox], [2.48])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux])
AC_PREFIX_DEFAULT([/usr])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.10 -Wall -Wno-portability foreign subdir-objects tar-pax])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT([disable-static])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_CXX
AM_CONDITIONAL([WITH_GNU_LD], [test "$with_gnu_ld" = yes])

saved_CPPFLAGS="$CPPFLAGS"
saved_CFLAGS="$CFLAGS"
saved_CXXFLAGS="$CXXFLAGS"
saved_LDFLAGS="$LDFLAGS"
saved_LIBS="$LIBS"
AC_LANG_PUSH([C++])

my_CPPFLAGS="-D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64"
my_CFLAGS="-Wall -Wmissing-declarations -Wwrite-strings"
my_CXXFLAGS="-Wall -Wmissing-declarations"
my_LDFLAGS=""
cxxmode="error"
AC_MSG_CHECKING([for C++ standard availability])
echo ""
for i in "" "c++26" "c++2c" "c++23" "c++2b" "c++20"; do
	dnl cov-scan cannot take too high a standard
	AS_IF([test -n "$COVERITY" && test "$i" != "c++20"], [continue])
	AC_MSG_CHECKING([if $CXX${i:+ -std=$i} works for our code])
	CXXFLAGS="$saved_CXXFLAGS${i:+ -std=$i}"
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([
		#include <span>
		#include <unordered_map>
		#include <vector>
		int main() {
			std::vector<int> v{1,9};
			std::span s = v;
			std::unordered_map<int, int> um{{}};
		}
	])], [
		AC_MSG_RESULT([yes])
		cxxmode="${i:+ -std=$i}"
		break
	], [
		AC_MSG_RESULT([no])
	])
done
CXXFLAGS="$saved_CXXFLAGS"
AS_IF([test "$cxxmode" = error], [
	AC_MSG_ERROR([None of the -std= flags we tried led to successful compilation, but we need C++20 support.])
])
my_CXXFLAGS="$my_CXXFLAGS${cxxmode}"

AC_ARG_ENABLE([private-headers],
	[AS_HELP_STRING([--enable-private-headers], [Do copy header files during \`make install\`])],
	[install_headers="$enableval"], [install_headers=no])
AM_CONDITIONAL([ENABLE_PRIVATE_HEADERS], [test "$install_headers" = yes])
AC_ARG_WITH([asan], AS_HELP_STRING([--with-asan], [Activate Address Sanitizer]),
	[
	my_CFLAGS="$my_CFLAGS -fsanitize=address"
	my_CXXFLAGS="$my_CXXFLAGS -fsanitize=address"
	my_LDFLAGS="$my_LDFLAGS -fsanitize=address"
	])
dnl fvis is non-conforming and (rightfully) triggers ubsan warnings;
dnl Only attempt visibility/ODR tricks when sanitizers are deactivated
dnl and when a good linker is available.
NO_VSYM=""
AC_ARG_WITH([ubsan], AS_HELP_STRING([--with-ubsan], [Activate Undefined Behavior Sanitizer]), [
	my_CFLAGS="$my_CFLAGS -fsanitize=undefined"
	my_CXXFLAGS="$my_CXXFLAGS -fsanitize=undefined"
	my_LDFLAGS="$my_LDFLAGS -fsanitize=undefined"
	NO_VSYM=1
])
AS_IF([test -z "$NO_VSYM"], [
	my_CFLAGS="$my_CFLAGS -fvisibility=hidden"
	my_CXXFLAGS="$my_CXXFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
])
AS_IF([test "$with_gnu_ld" != yes], [NO_VSYM=1])
AC_SUBST([NO_VSYM])


AC_ARG_WITH([unitdir],
	[AS_HELP_STRING([--with-unitdir=PATH], [Path to systemd service unit directory])],
	[unitdir="$withval"],
	[
		unitdir=$("$PKG_CONFIG" systemd --variable systemdsystemunitdir 2>/dev/null)
		AS_IF([test -z "$unitdir"], [unitdir='${prefix}/lib/systemd/system'])
	])
AC_SUBST([unitdir])

dnl
dnl The cstring header comes from the compiler, but ::strchr comes from the
dnl C library. If the two are not synced up, a problem ensues.
dnl
AC_MSG_CHECKING([for a complete C++ environment])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
	#include <cstring>
	int main() { auto a = ""; auto r = std::strchr(a, '/'); r = a; }
])], [
	AC_MSG_RESULT([ok])
], [
	AC_MSG_RESULT([no])
	echo "***"
	echo "*** The const versions of C string functions are absent."
	echo "*** That's a bug in your toolchain combination."
	echo "***"
	# grep for CONST-STRCHR-MARKER
])
crypt_LIBS=""
dl_LIBS=""
libldap_LIBS=""
pam_LIBS=""
resolv_LIBS=""
AH_TEMPLATE([HAVE_CARES], [])
AH_TEMPLATE([HAVE_ESEDB], [])
AH_TEMPLATE([HAVE_GSSAPI], [])
AH_TEMPLATE([HAVE_XXHASH], [])
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([fmt], [fmt >= 8])
PKG_CHECK_MODULES([jsoncpp], [jsoncpp >= 1.4.0], [], [
	PKG_CHECK_MODULES([jsoncpp], [jsoncpp >= 0.8 jsoncpp < 1])
])
PKG_CHECK_MODULES([gss], [krb5-gssapi], [
	AC_DEFINE([HAVE_GSSAPI], [1])
], [:])
PKG_CHECK_MODULES([libHX], [libHX >= 4.27])
PKG_CHECK_MODULES([libcrypto], [libcrypto])
PKG_CHECK_MODULES([libcurl], [libcurl])
PKG_CHECK_MODULES([libesedb], [libesedb], [have_esedb=1], [have_esedb=0])
PKG_CHECK_MODULES([libldap], [ldap], [], [
	AC_CHECK_HEADERS([ldap.h], [], [AC_MSG_ERROR([ldap.h is required])])
	AC_SEARCH_LIBS([ldap_init], [ldap_r ldap], [libldap_LIBS="$LIBS"; LIBS=""], [AC_MSG_ERROR([libldap is required])])
	AC_SUBST([libldap_LIBS])
])
PKG_CHECK_MODULES([libolecf], [libolecf], [have_olecf=1], [have_olecf=0])
PKG_CHECK_MODULES([libpff], [libpff], [have_pff=1], [have_pff=0])
PKG_CHECK_MODULES([libssl], [libssl])
PKG_CHECK_MODULES([libxml2], [libxml-2.0])
PKG_CHECK_MODULES([libxxhash], [libxxhash >= 0.7], [have_xxhash=1], [have_xxhash=0])
PKG_CHECK_MODULES([libzstd], [libzstd >= 1.4])
PKG_CHECK_MODULES([sqlite], [sqlite3])
PKG_CHECK_MODULES([tinyxml2], [tinyxml2 >= 8])
PKG_CHECK_MODULES([vmime], [wmime >= 1])
PKG_CHECK_MODULES([zlib], [zlib])
dnl Linux-PAM only gained a .pc file in v1.5.1-41-gb4f0e2e1 (2021)
have_pamheader=""
AC_CHECK_HEADERS([crypt.h syslog.h])
AC_CHECK_HEADERS([sys/epoll.h sys/event.h sys/ioctl.h sys/random.h sys/vfs.h sys/xattr.h])
AC_CHECK_HEADERS([security/pam_modules.h], [have_pamheader="yes"])
AM_CONDITIONAL([HAVE_ESEDB], [test "$have_esedb" = 1])
AM_CONDITIONAL([HAVE_PAM], [test "$have_pamheader" = yes])
AM_CONDITIONAL([HAVE_OLECF], [test "$have_olecf" = 1])
AM_CONDITIONAL([HAVE_PFF], [test "$have_pff" = 1])
AM_CONDITIONAL([HAVE_XXHASH], [test "$have_xxhash" = 1])
AS_IF([test "$have_esedb" = 1], [AC_DEFINE([HAVE_ESEDB], [1], [])])
AS_IF([test "$have_xxhash" = 1], [AC_DEFINE([HAVE_XXHASH], [1], [])])
AC_CHECK_FUNCS([fsetxattr posix_fadvise])
AC_SEARCH_LIBS([crypt], [crypt], [crypt_LIBS="$LIBS"; LIBS=""])
AC_SEARCH_LIBS([dlopen], [dl], [dl_LIBS="$LIBS"; LIBS=""])
AC_SEARCH_LIBS([ns_initparse], [resolv], [resolv_LIBS="$LIBS"; LIBS=""])
AC_SEARCH_LIBS([pam_get_item], [pam], [pam_LIBS="$LIBS"; LIBS=""])
LIBS="$LIBS $resolv_LIBS"
AH_TEMPLATE([HAVE_RES_NQUERYDOMAIN], [])
AC_MSG_CHECKING([for res_nquerydomain])
AC_LINK_IFELSE(
	dnl It is a macro on some older systems
	[AC_LANG_SOURCE([
		#include <resolv.h>
		int main() { res_nquerydomain(0,0,0,0,0,0,0); }
	])],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_RES_NQUERYDOMAIN], [1])
		have_res_nq=1
	],
	[
		AC_MSG_RESULT([no])
		have_res_nq=0
	]
)
LIBS="$saved_LIBS"
AS_IF([test "$have_res_nq" = 0], [
	PKG_CHECK_MODULES([cares], [libcares], [AC_DEFINE([HAVE_CARES], [1])], [:])
])

AC_SUBST([crypt_LIBS])
AC_SUBST([dl_LIBS])
AC_SUBST([pam_LIBS])
AC_SUBST([resolv_LIBS])
dnl
dnl Can't use AC_SEARCH_LIBS([iconv_open]) because that does not process
dnl the "#define iconv_open libiconv_open" macro that some iconv
dnl implementations have.
dnl
iconv_CPPFLAGS=""
iconv_set=0
AC_MSG_CHECKING([for library containing iconv_open])
for i in "" "-liconv"; do
	LIBS="$LIBS $i"
	AC_LINK_IFELSE([AC_LANG_SOURCE([
		#include <iconv.h>
		int main() { iconv_open("", ""); return 0; }
	])], [
		iconv_LIBS="$i"
		iconv_set=1
		break
	])
done
LIBS="$saved_LIBS"
AS_IF([test "$iconv_set" = 0], [
	AC_MSG_RESULT([none found])
	AS_CASE([$host_os],
		[openbsd*|freebsd*], [AC_MSG_ERROR([Could not locate a usable iconv_open; you may need to pass CPPFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib])],
		[*], [AC_MSG_ERROR([Could not locate a usable iconv_open])]
	)
], [test -z "$iconv_LIBS"], [
	AC_MSG_RESULT([none required])
], [
	AC_MSG_RESULT([$iconv_LIBS])
])
AC_SUBST([iconv_CPPFLAGS])
AC_SUBST([iconv_LIBS])

AC_PATH_PROGS([MYSQL_CONFIG], [mysql_config mariadb_config])
AC_ARG_WITH([mysql-config], AS_HELP_STRING([--with-mysql-config=PATH], [Path to the mysql_config/mariadb_config script]),
	[MYSQL_CONFIG="$withval"])
AS_IF([test -z "$MYSQL_CONFIG"], [AC_MSG_ERROR([mysql_config/mariadb_config program not found])])
mysql_VERSION=$($MYSQL_CONFIG --version) # see if it exists at all
AS_IF([test -z "$mysql_VERSION"], [AC_MSG_ERROR([Cannot find a MySQL/MariaDB client installation.])])
mysql_CFLAGS=$($MYSQL_CONFIG --include)
mysql_LIBS=$($MYSQL_CONFIG --libs)
AC_SUBST([mysql_CFLAGS])
AC_SUBST([mysql_LIBS])
AC_SUBST([mysql_VERSION])
AC_MSG_CHECKING([for MySQL includes])
AC_MSG_RESULT([$mysql_CFLAGS])
AC_MSG_CHECKING([for MySQL libs])
AC_MSG_RESULT([$mysql_LIBS])

sysusersdir=$("$PKG_CONFIG" systemd --variable sysusersdir 2>/dev/null)
tmpfilesdir=$("$PKG_CONFIG" systemd --variable tmpfilesdir 2>/dev/null)
AC_ARG_WITH([dcprefix],
	[AS_HELP_STRING([Extra path inserted for distcheck])],
	[dcprefix="$withval"])
AS_IF([test -z "$unitdir"], [unitdir='${prefix}/lib/systemd/system'], [unitdir='${dcprefix}'"$unitdir"])
AS_IF([test -z "$sysusersdir"], [sysusersdir='${prefix}/lib/sysusers.d'], [sysusersdir='${dcprefix}'"$sysusersdir"])
AS_IF([test -z "$tmpfilesdir"], [tmpfilesdir='${prefix}/lib/tmpfiles.d'], [tmpfilesdir='${dcprefix}'"$tmpfilesdir"])
AC_SUBST([unitdir])
AC_SUBST([sysusersdir])
AC_SUBST([tmpfilesdir])
AC_SUBST([dcprefix])

AC_ARG_WITH([php], [
		AS_HELP_STRING([--with-php=/usr/bin/php-config], [Enable building PHP modules])
		AS_HELP_STRING([--without-php], [Disable building PHP modules])
	],
	[PHP_CONFIG="$withval"],
	[
	dnl OpenBSD uses php-config-N, Debian php-configN
	AC_PATH_PROGS([PHP_CONFIG], [php-config php-config-8.4 php-config84 php-config-8.3 php-config8.3 php-config83 php-config-8.2 php-config8.2 php-config82 php-config-8.1 php-config8.1 php-config81 php-config-8.0 php-config8.0 php-config80 php-config-7.4 php-config7.4 php-config74])
	dnl Set something so the error messages make more sense
	AS_IF([test -z "$PHP_CONFIG"], [PHP_CONFIG="php-config"])
])
AS_IF([test "$with_php" != "no"], [
	PHP_WITH_PHP_CONFIG
	CPPFLAGS="$saved_CPPFLAGS"
	CFLAGS="$saved_CFLAGS"
	CXXFLAGS="$saved_CXXFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
])
AM_CONDITIONAL([HAVE_PHP], [test "$with_php" != no])

AC_SUBST([my_CPPFLAGS])
AC_SUBST([my_CFLAGS])
AC_SUBST([my_CXXFLAGS])
AC_SUBST([my_LDFLAGS])

AS_IF([test -z "$cxxmode"], [AC_MSG_RESULT([*** No usable -std= argument was detected for this C++ compiler.])])
AC_LANG_POP([C++])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
echo "Install private headers: $install_headers"
