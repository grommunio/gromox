# -*- Mode: autoconf -*-
# php.m4 for configure scripts to check for php development files
# exports the following variables:
#  PHP_INCLUDES
#  PHP_LDFLAGS
#  PHP_EXTENSION_DIR
#  PHP_VERSION

AC_DEFUN([PHP_WITH_PHP_CONFIG],[
	PHP_INCLUDES=$($PHP_CONFIG --includes)
	PHP_LDFLAGS=$($PHP_CONFIG --ldflags)
	PHP_EXTENSION_DIR=$($PHP_CONFIG --extension-dir)
	AS_IF([test "$?" -ne 0], [AC_MSG_ERROR([Cannot execute $PHP_CONFIG])])
	AC_MSG_CHECKING([for PHP])
	PHP_VERSION=$($PHP_CONFIG --version)
	AC_MSG_RESULT([$PHP_VERSION])
	PHP_SYSCONF_DIR=$($PHP_CONFIG --ini-dir)
	if test -z "${PHP_SYSCONF_DIR}"; then
	if test -d "/etc/php.d"; then
		PHP_SYSCONF_DIR="/etc/php.d"
	elif test -d "/etc/php8/conf.d"; then
		PHP_SYSCONF_DIR="/etc/php8/conf.d"
	elif test -d "/etc/php8/apache2/conf.d"; then
		PHP_SYSCONF_DIR="/etc/php8/apache2/conf.d"
	elif test -d "/etc/php7/conf.d"; then
		PHP_SYSCONF_DIR="/etc/php7/conf.d"
	elif test -d "/etc/php7/apache2/conf.d"; then
		PHP_SYSCONF_DIR="/etc/php7/apache2/conf.d"
	else
		AC_MSG_ERROR([Cannot find php-ini dir])
	fi
	fi
	AC_SUBST(PHP_SYSCONF_DIR)
	AC_SUBST(PHP_INCLUDES)
	AC_SUBST(PHP_LDFLAGS)
	AC_SUBST(PHP_EXTENSION_DIR)
	AC_SUBST(PHP_VERSION)

	AC_MSG_CHECKING([for PHP includes])
	AC_MSG_RESULT($PHP_INCLUDES)
	AC_MSG_CHECKING([for PHP extension directory])
	AC_MSG_RESULT($PHP_EXTENSION_DIR)
	AC_MSG_CHECKING([for PHP ini directory])
	AC_MSG_RESULT($PHP_SYSCONF_DIR)
])
