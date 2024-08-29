<?php
$hostname = "a4.inai.de";
$options = getopt("a:b:u:p:", array("login-only"));
var_dump($options);
$pass ??= $options["p"];
$start  = $options["a"] ?? 3000;
$end    = $options["b"] ?? 4000;
include_once("/usr/share/php-mapi/mapi.util.php");
include_once("/usr/share/php-mapi/mapidefs.php");
include_once("/usr/share/php-mapi/mapitags.php");
include_once("/usr/share/php-mapi/mapiguid.php");
for ($i = $start; $i < $end; ++$i) {
	$user = "u$i@$hostname";
	$session = mapi_logon_zarafa($user, $pass, "", null, null, 0, "script", "script");
	if (!$session) {
		print("Login failed for $user\n");
		break;
	}
	print "$user\n";
	if (isset($options["login-only"]))
		continue;
	$tbl = mapi_getmsgstorestable($session);
	$rows = mapi_table_queryallrows($tbl, array(PR_ENTRYID, PR_DEFAULT_STORE));
	foreach ($rows as $row) {
		if (isset($row[PR_DEFAULT_STORE]) && $row[PR_DEFAULT_STORE] == true) {
			$entryid = $row[PR_ENTRYID];
			break;
		}
	}
	$store = @mapi_openmsgstore($session, $entryid);
	$props = mapi_getprops($store, array(PR_COMMENT));
}
