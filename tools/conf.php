<?php
function remove_quotes_assocarray($a) {
    foreach ($a as $k => $v) {
        $a[$k] = str_replace("'","",$a[$k]);
    }
    return $a;
}
function get_app_config()
{
	static $appconf = NULL;
	
	if ($appconf) {
		return $appconf;
	}
	if (file_exists("/etc/gromox/mysql_adaptor.cfg")) {
		$b = remove_quotes_assocarray(parse_ini_file("/etc/gromox/mysql_adaptor.cfg", false, INI_SCANNER_RAW));
		if ($b === false)
			$b = [];
	}
	$b["mysql_host"] ??= "localhost";
	$b["mysql_username"] ??= "root";
	$b["mysql_password"] ??= "";
	$b["mysql_dbname"] ??= "email";

	if (file_exists("/etc/gromox/autodiscover.ini")) {
		$a = remove_quotes_assocarray(parse_ini_file("/etc/gromox/autodiscover.ini", true, INI_SCANNER_RAW));
		if ($a === false)
			$a = [];
	} else {
		$a = [];
	}
	$a["database"] ??= [];
	$a["database"]["host"] ??= $b["mysql_host"];
	$a["database"]["username"] ??= $b["mysql_username"];
	$a["database"]["password"] ??= $b["mysql_password"];
	$a["database"]["dbname"] ??= $b["mysql_dbname"];

	$a["exchange"] ??= [];
	$a["exchange"]["organization"] ??= "Gromox default";
	$a["exchange"]["hostname"] ??= gethostname();
	$a["exchange"]["mapihttp"] ??= 0;

	$a["default"] ??= [];
	$a["default"]["timezone"] ??= "Europe/Vienna";

	$a["http-proxy"] ??= [];
	$a["http-proxy"]["/var/lib/gromox/user/"] ??= $a["exchange"]["hostname"];
	$a["http-proxy"]["/var/lib/gromox/domain/"] ??= $a["exchange"]["hostname"];

	return $a;
}

?>