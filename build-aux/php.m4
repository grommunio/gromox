# -*- Mode: autoconf -*-
# php.m4 for configure scripts to check for php development files
# exports the following variables:
#  PHP_INCLUDES
#  PHP_LDFLAGS
#  PHP_EXTENSION_DIR
#  PHP_VERSION

AC_DEFUN([PHP_WITH_PHP_CONFIG],[
	AC_ARG_WITH(php-config, AC_HELP_STRING([--with-php-config=PATH],[path to the php-config script]),
		[PHP_CONFIG=${withval}],[PHP_CONFIG=php-config])

	AC_MSG_CHECKING([for PHP])
	if ! test -x "$(which $PHP_CONFIG 2>/dev/null)"; then
		AC_MSG_ERROR([Cannot execute $PHP_CONFIG])
	fi
	PHP_INCLUDES=$($PHP_CONFIG --includes)
	PHP_LDFLAGS=$($PHP_CONFIG --ldflags)
	PHP_EXTENSION_DIR=$($PHP_CONFIG --extension-dir)
	PHP_VERSION=$($PHP_CONFIG --version)
	# watch escaping for brackets, only take the first word (2nd sed). will contain "Usage:" when php doesn't understand the --configure-options parameter.
	PHP_SYSCONF_DIR=$($PHP_CONFIG --configure-options | sed -e 's_.*with-config-file-scan-dir=\([[^ ]]\+\).*_\1_' | sed -e 's/\([[^ ]]\+\).*/\1/')
	phpdn=$(dirname "$PHP_SYSCONF_DIR")
	if test -z "${PHP_SYSCONF_DIR}" -o "${phpdn}" = "."; then
	# find path in existing paths
	if test -d "/etc/php.d"; then
		PHP_SYSCONF_DIR="/etc/php.d"
	elif test -d "/etc/php7/conf.d"; then
		PHP_SYSCONF_DIR="/etc/php7/conf.d"
	elif test -d "/etc/php7/apache2/conf.d"; then
		PHP_SYSCONF_DIR="/etc/php7/apache2/conf.d"
	elif test -d "/etc/php5/conf.d"; then
		PHP_SYSCONF_DIR="/etc/php5/conf.d"
	elif test -d "/etc/php5/apache2/conf.d"; then
		PHP_SYSCONF_DIR="/etc/php5/apache2/conf.d"
		elif test -d "/etc/opt/rh/rh-php70/php.d"; then
		    # For PHP7 builds on rhel/centos 7 the php-config has no configure-options, setting php sysconf path manually
		    PHP_SYSCONF_DIR="/etc/opt/rh/rh-php70/php.d"
	else
		# this happens on old distributions
	    AC_MSG_RESULT([Cannot find php sysconf path, forcing /usr/share/doc/kopano])
		PHP_SYSCONF_DIR="/usr/share/doc/kopano"
	fi
	fi
	if test ! -d "${PHP_SYSCONF_DIR}"; then
		AC_MSG_WARN([$PHP_CONFIG returned sysconf scan dir "$PHP_SYSCONF_DIR", however this directory does not (yet) exist])
	fi
	AC_SUBST(PHP_SYSCONF_DIR)

	if test -z "$PHP_EXTENSION_DIR"; then
		AC_MSG_ERROR(Cannot find php-config. Please use --with-php-config=PATH)
	fi

	AC_SUBST(PHP_INCLUDES)
	AC_SUBST(PHP_LDFLAGS)
	AC_SUBST(PHP_EXTENSION_DIR)
	AC_SUBST(PHP_VERSION)

	AC_MSG_CHECKING([for PHP includes])
	AC_MSG_RESULT($PHP_INCLUDES)
	AC_MSG_CHECKING([for PHP extension directory])
	AC_MSG_RESULT($PHP_EXTENSION_DIR)
	AC_MSG_CHECKING([for PHP config scan directory])
	AC_MSG_RESULT($PHP_SYSCONF_DIR)
])

dnl php-config can be in a different package that the header files (suse 9.1)
dnl so we explicitly check if something would compile with the found include parameters
AC_DEFUN([PHP_CHECK_INCLUDES],[
CFLAGS="$CFLAGS $PHP_INCLUDES"
CXXFLAGS="$CXXFLAGS $PHP_INCLUDES"
AC_MSG_CHECKING([acquired PHP settings])
AC_LINK_IFELSE([
 AC_LANG_SOURCE([
#include <php.h>
int main() {
	zval *ptr = NULL;
}
 ]) ], [ AC_MSG_RESULT([ok]) ], [ AC_MSG_ERROR([broken])
])
CXXFLAGS=$CXXFLAGS_system
])
