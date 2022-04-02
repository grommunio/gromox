<?php

function get_athena_config()
{
	static $sysconf = NULL;
	
	if ($sysconf) {
		return $sysconf;
	}
	$z = parse_ini_file("/etc/gromox/mysql_adaptor.cfg", false, INI_SCANNER_RAW);
	if (!isset($z))
		die("cannot find config.ini file");
	$sysconf = array();
	foreach ($z as $k => &$v)
		$sysconf[strtoupper($k)] = $v;
	return $sysconf;
}

?>