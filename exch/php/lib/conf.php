<?php
function get_app_config()
{
	static $appconf = NULL;
	
	if ($appconf) {
		return $appconf;
	}
	$a = @parse_ini_file("/etc/gromox/autodiscover.ini", true);
	if ($a === false)
		$a = [];
	$a["database"] ??= [];
	$a["database"]["host"] ??= "localhost";
	$a["database"]["username"] ??= "root";
	$a["database"]["password"] ??= "";
	$a["database"]["dbname"] ??= "email";

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