<?php

function get_db_connection()
{
	static $dbconn = NULL;
	
	if ($dbconn) {
		return $dbconn;
	}
	require_once "conf.php";
	$config = get_athena_config();
	if (empty($config['MYSQL_HOST'])) {
		die("cannot find MYSQL_HOST in config file");
	}
	if (empty($config['MYSQL_PORT'])) {
		die("cannot find MYSQL_PORT in config file");
	}
	if (empty($config['MYSQL_USERNAME'])) {
		die("cannot find MYSQL_USERNAME in config file");
	}
	if (empty($config['MYSQL_PASSWORD'])) {
		die("cannot find MYSQL_PASSWORD in config file");
	}
	if (empty($config['MYSQL_DBNAME'])) {
		die("cannot find MYSQL_DBNAME in config file");
	}
	$dbconn = mysql_connect($config['MYSQL_HOST'] . ':' . $config['MYSQL_PORT'],
							$config['MYSQL_USERNAME'], $config['MYSQL_PASSWORD']);
	if (!$dbconn) {
		die("fail to connect to database server: " . mysql_error());
	}
	if (mysql_select_db($config['MYSQL_DBNAME'], $dbconn) == false) {
		die("fail to select database");
	}
	return $dbconn;
}

function get_user_id($account)
{
	$db_conn = get_db_connection();
	
	$sql_string = "SELECT id FROM users WHERE username='" . mysql_real_escape_string($account) . "'";
	$results = mysql_query($sql_string, $db_conn);
	if (!$results) {
		die("fail to query database: " . mysql_error());
	}
	if (1 != mysql_num_rows($results)) {
		return false;
	}
	$row = mysql_fetch_row($results);
	return $row[0];
}

?>