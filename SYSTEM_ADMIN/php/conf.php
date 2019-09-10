<?php

function get_athena_config()
{
	static $sysconf = NULL;
	
	if ($sysconf) {
		return $sysconf;
	}
	$sysconf = parse_ini_file("../config/athena.cfg", false, INI_SCANNER_RAW);
	if (!isset($sysconf)) {
		die("cannot find config.ini file");
	}
	return $sysconf;
}

?>