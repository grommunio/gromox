<?php
$user = $argv[1];
$pass = $argv[2];
include_once("/usr/share/php-mapi/mapi.util.php");
include_once("/usr/share/php-mapi/mapidefs.php");
include_once("/usr/share/php-mapi/mapitags.php");
include_once("/usr/share/php-mapi/mapiguid.php");
for ($i = 0; $i < 1000; ++$i) {
	$session = mapi_logon_zarafa($user, $pass, "", null, null, 0, "script", "script");
	if (!$session) {
		print("Login failed\n");
		break;
	}
}
