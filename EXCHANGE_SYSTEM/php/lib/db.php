<?php


function get_db_connection()
{
	static $dbconn = NULL;
	
	if ($dbconn) {
		return $dbconn;
	}
	require_once "conf.php";
	$config = get_app_config();
	$db_config = $config['database'];
	if (!isset($db_config)) {
		die("cannot find [database] section in config file");
	}
	if (!isset($db_config['host'])) {
		die("cannot find host under [database] in config file");
	}
	if (!isset($db_config['username'])) {
		die("cannot find username under [database] in config file");
	}
	if (!isset($db_config['password'])) {
		die("cannot find password under [database] in config file");
	}
	if (!isset($db_config['dbname'])) {
		die("cannot find dbname under [database] in config file");
	}
	$dbconn = mysql_connect($db_config['host'], $db_config['username'], $db_config['password']);
	if (!$dbconn) {
		die("fail to connect to database server: " . mysql_error());
	}
	if (mysql_select_db($db_config['dbname'], $dbconn) == false) {
		die("fail to select database");
	}
	return $dbconn;
}

function get_user_info_by_name($email_address)
{
	$db_conn = get_db_connection();
	
	$sql_string = "SELECT maildir, real_name, username, id, domain_id, timezone FROM users WHERE username='" . mysql_real_escape_string($email_address) . "'";
	$results = mysql_query($sql_string, $db_conn);
	if (!$results) {
		die("fail to query database: " . mysql_error());
	}
	if (1 != mysql_num_rows($results)) {
		return NULL;
	}
	$row = mysql_fetch_row($results);
	$at_pos = strpos($row[2], '@');
	$domain = substr($row[2], $at_pos + 1);
	if (!$row[5]) {
		$config = get_app_config();
		$timezone = $config['default']['timezone'];
		if (!$timezone) {
			$timezone = "Asia/Shanghai";
		}
	} else {
		$timezone = $row[5];
	}
	return array('maildir'=>$row[0], 'real_name'=>$row[1], 'username'=>$row[2], 'domain'=>$domain, 'uid'=>$row[3], 'did'=>$row[4], 'timezone'=>$timezone);
}

function get_user_info_by_id($user_id)
{
	$db_conn = get_db_connection();
	
	$sql_string = "SELECT maildir, real_name, username, id, domain_id, timezone FROM users WHERE id=" . $user_id;
	$results = mysql_query($sql_string, $db_conn);
	if (!$results) {
		die("fail to query database: " . mysql_error());
	}
	if (1 != mysql_num_rows($results)) {
		return NULL;
	}
	$row = mysql_fetch_row($results);
	$at_pos = strpos($row[2], '@');
	$domain = substr($row[2], $at_pos + 1);
	if (!$row[5]) {
		$config = get_app_config();
		$timezone = $config['default']['timezone'];
		if (!$timezone) {
			$timezone = "Asia/Shanghai";
		}
	} else {
		$timezone = $row[5];
	}
	return array('maildir'=>$row[0], 'real_name'=>$row[1], 'username'=>$row[2], 'domain'=>$domain, 'uid'=>$row[3], 'did'=>$row[4], 'timezone'=>$timezone);
}

function get_domain_info_by_name($domain)
{
	$db_conn = get_db_connection();
	
	$sql_string = "SELECT homedir, id, domainname FROM domains WHERE domainname='" . mysql_real_escape_string($domain) . "'";
	$results = mysql_query($sql_string, $db_conn);
	if (!$results) {
		die("fail to query database: " . mysql_error());
	}
	if (1 != mysql_num_rows($results)) {
		return NULL;
	}
	$row = mysql_fetch_row($results);
	return array('homedir'=>$row[0], 'did'=>$row[1], 'domain'=>$row[2]);
}

function get_domain_info_by_id($domain_id)
{
	$db_conn = get_db_connection();
	
	$sql_string = "SELECT homedir, id, domainname FROM domains WHERE id=" . $domain_id;
	$results = mysql_query($sql_string, $db_conn);
	if (!$results) {
		die("fail to query database: " . mysql_error());
	}
	if (1 != mysql_num_rows($results)) {
		return NULL;
	}
	$row = mysql_fetch_row($results);
	return array('homedir'=>$row[0], 'did'=>$row[1], 'domain'=>$row[2]);
}

?>
