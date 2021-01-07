<?php

require_once "env.php";

function get_app_config()
{
	static $appconf = NULL;
	
	if ($appconf) {
		return $appconf;
	}
	$appconf = parse_ini_file(APP_PATH . "config/config.ini", true);
	if (!isset($appconf)) {
		die("cannot find config.ini file");
	}
	return $appconf;
}

?>