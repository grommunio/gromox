<?php


function get_db_connection()
{
	static $db_conn = NULL;
	
	if ($db_conn) {
		return $db_conn;
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
	$db_conn = mysqli_connect($db_config['host'], $db_config['username'], $db_config['password'], $db_config['dbname']);
	if ($db_conn->connect_errno) {
		die("fail to connect to database server: " . $db_conn->connect_error);
	}
	return $db_conn;
}

function get_user_info_by_name($email_address)
{
	$db_conn = get_db_connection();
	
	$sql_string = "SELECT maildir, real_name, username, id, domain_id, timezone FROM users WHERE username='" . $db_conn->real_escape_string($email_address) . "'";
	$results = $db_conn->query($sql_string);
	if (!$results) {
		die("fail to query database: " . $db_conn->error);
	}
	if (1 != mysqli_num_rows($results)) {
		return NULL;
	}
	$row = $results->fetch_row();
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
	$results = $db_conn->query($sql_string);
	if (!$results) {
		die("fail to query database: " . $db_conn->error);
	}
	if (1 != mysqli_num_rows($results)) {
		return NULL;
	}
	$row = $results->fetch_row();
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
	
	$sql_string = "SELECT homedir, id, domainname FROM domains WHERE domainname='" . $db_conn->real_escape_string($domain) . "'";
	$results = $db_conn->query($sql_string);
	if (!$results) {
		die("fail to query database: " . $db_conn->error);
	}
	if (1 != mysqli_num_rows($results)) {
		return NULL;
	}
	$row = $results->fetch_row();
	return array('homedir'=>$row[0], 'did'=>$row[1], 'domain'=>$row[2]);
}

function get_domain_info_by_id($domain_id)
{
	$db_conn = get_db_connection();
	
	$sql_string = "SELECT homedir, id, domainname FROM domains WHERE id=" . $domain_id;
	$results = $db_conn->query($sql_string);
	if (!$results) {
		die("fail to query database: " . $db_conn->error);
	}
	if (1 != mysqli_num_rows($results)) {
		return NULL;
	}
	$row = $results->fetch_row();
	return array('homedir'=>$row[0], 'did'=>$row[1], 'domain'=>$row[2]);
}

function get_domains()
{
	$db_conn = get_db_connection();

	$sql_string = "SELECT domainname FROM domains";
	$results = $db_conn->query($sql_string);
	if (!$results) {
		die("fail to query database: " . $db_conn->error);
	}
	$domains = array();
	for ($i = 0; $i < mysqli_num_rows($results); ++$i) {
		$row = $results->fetch_row();
		$domains[] = $row[0];
	}
	return $domains;
}

?>
