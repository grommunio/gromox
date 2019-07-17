PHP_ARG_ENABLE(mapi, whether to enable php-mapi support,
[ --enable-mapi   Enable php-mapi support])

if test "$PHP_MAPI" = "yes"; then
	AC_DEFINE(HAVE_MAPI, 1, [Whether you have php-mapi])
	PHP_NEW_EXTENSION(mapi, mapi.c type_conversion.c ext_pack.c rpc_ext.c zarafa_client.c, $ext_shared)
fi
