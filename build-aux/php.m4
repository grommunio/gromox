# -*- Mode: autoconf -*-
# php.m4 for configure scripts to check for php development files
# exports the following variables:
#  PHP_INCLUDES
#  PHP_LDFLAGS
#  PHP_EXTENSION_DIR
#  PHP_VERSION

AC_DEFUN([PHP_WITH_PHP_CONFIG],[
	AC_MSG_CHECKING([for PHP])
	PHP_VERSION=$($PHP_CONFIG --version)
	AS_IF([test "$?" -ne 0], [AC_MSG_ERROR([Cannot execute $PHP_CONFIG])])
	AC_MSG_RESULT([$PHP_VERSION])
	AC_SUBST([PHP_VERSION])

	AC_MSG_CHECKING([for PHP includes])
	PHP_INCLUDES=$($PHP_CONFIG --includes)
	PHP_LDFLAGS=$($PHP_CONFIG --ldflags)
	AC_MSG_RESULT([$PHP_INCLUDES])
	AC_SUBST([PHP_INCLUDES])
	AC_SUBST([PHP_LDFLAGS])

	AC_MSG_CHECKING([for PHP extension directory])
	PHP_EXTENSION_DIR=$($PHP_CONFIG --extension-dir)
	AC_MSG_RESULT([$PHP_EXTENSION_DIR])
	AC_SUBST([PHP_EXTENSION_DIR])

	AC_MSG_CHECKING([for PHP ini directory])
	PHP_SYSCONF_DIR=$($PHP_CONFIG --ini-dir)
	AS_IF([test "$?" -ne 0], [PHP_SYSCONF_DIR=""])
	AS_IF([test -z "${PHP_SYSCONF_DIR}"], [AS_IF(
		[test -d "/etc/php.d"],               [PHP_SYSCONF_DIR="/etc/php.d"],
		[test -d "/etc/php8/conf.d"],         [PHP_SYSCONF_DIR="/etc/php8/conf.d"],
		[test -d "/etc/php8/apache2/conf.d"], [PHP_SYSCONF_DIR="/etc/php8/apache2/conf.d"],
		[test -d "/etc/php7/conf.d"],         [PHP_SYSCONF_DIR="/etc/php7/conf.d"],
		[test -d "/etc/php7/apache2/conf.d"], [PHP_SYSCONF_DIR="/etc/php7/apache2/conf.d"],
		dnl Let packagers figure it out
		[PHP_SYSCONF_DIR='${pkgdatadir}/php.conf.d']
	)])
	AC_MSG_RESULT($PHP_SYSCONF_DIR)
	AC_SUBST([PHP_SYSCONF_DIR])
])
