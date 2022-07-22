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
		_log_db("cannot find [database] section in config file");
	}
	if (!isset($db_config['host'])) {
		_log_db("cannot find host under [database] in config file");
	}
	if (!isset($db_config['username'])) {
		_log_db("cannot find username under [database] in config file");
	}
	if (!isset($db_config['password'])) {
		_log_db("cannot find password under [database] in config file");
	}
	if (!isset($db_config['dbname'])) {
		_log_db("cannot find dbname under [database] in config file");
	}
	$db_conn = mysqli_connect($db_config['host'], $db_config['username'], $db_config['password'], $db_config['dbname']);
	$e = mysqli_connect_errno();
	if ($e != 0) {
		_log_db("Failed to connect to database server: " . $e);
	}
	return $db_conn;
}

function get_user_info_by_name($email_address)
{
	$db_conn = get_db_connection();

	$sql_string = "SELECT maildir, '', username, id, domain_id, timezone FROM users WHERE username='" . $db_conn->real_escape_string($email_address) . "'";
	$results = $db_conn->query($sql_string);
	if (!$results) {
		_log_db("fail to query database: " . $db_conn->error);
	}
	if (1 != mysqli_num_rows($results)) {
		return NULL;
	}
	$row = $results->fetch_row();
	$data_array = array(
		"maildir" => $row[0],
		"username" => $row[2],
		"uid" => $row[3],
		"did" => $row[4],
	);
	$pos = strpos($row[2], '@');
	$data_array["domain"] = $pos !== false ? substr($row[2], $pos + 1) : "";
	if (!$row[5]) {
		$config = get_app_config();
		$data_array["timezone"] = $config['default']['timezone'];
		if (!$data_array["timezone"])
			/* see gromox/defs.h */
			$data_array["timezone"] = "Pacific/Chatham";
	} else {
		$data_array["timezone"] = $row[5];
	}

	$sql_string = "SELECT proptag, propval_str FROM users INNER JOIN user_properties AS up ON users.id=up.user_id WHERE users.username='" . $db_conn->real_escape_string($email_address) . "'";
	$results = $db_conn->query($sql_string);
	if (!$results)
		_log_db("failed to query database: " . $db_conn->error);
	$data_array["real_name"] = "";
	while (($row = $results->fetch_row())) {
		if ($row[0] == 805371935)
			$data_array["real_name"] = $row[1];
	}
	return $data_array;
}

function get_user_info_by_id($user_id)
{
	$db_conn = get_db_connection();

	$sql_string = "SELECT maildir, '', username, id, domain_id, timezone FROM users WHERE id=" . $user_id;
	$results = $db_conn->query($sql_string);
	if (!$results) {
		_log_db("fail to query database: " . $db_conn->error);
	}
	if (1 != mysqli_num_rows($results)) {
		return NULL;
	}
	$row = $results->fetch_row();
	$data_array = array(
		"maildir" => $row[0],
		"username" => $row[2],
		"domain" => substr($row[2], strpos($row[2], '@')),
		"uid" => $row[3],
		"did" => $row[4],
	);
	if (!$row[5]) {
		$config = get_app_config();
		$data_array["timezone"] = $config['default']['timezone'];
		if (!$data_array["timezone"])
			$data_array["timezone"] = "Pacific/Chatham"; /* gromox/defs.h */
	} else {
		$data_array["timezone"] = $row[5];
	}

	$sql_string = "SELECT proptag, propval_str FROM users INNER JOIN user_properties AS up ON users.id=up.user_id WHERE users.id=" . $user_id;
	$results = $db_conn->query($sql_string);
	if (!$results)
		_log_db("failed to query database: " . $db_conn->error);
	while (($row = $results->fetch_row())) {
		if ($row[0] == 805371935)
			$data_array["real_name"] = $row[1];
	}
	return $data_array;
}

function get_domain_info_by_name($domain)
{
	$db_conn = get_db_connection();

	$sql_string = "SELECT homedir, id, domainname FROM domains WHERE domainname='" . $db_conn->real_escape_string($domain) . "'";
	$results = $db_conn->query($sql_string);
	if (!$results) {
		_log_db("fail to query database: " . $db_conn->error);
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
		_log_db("fail to query database: " . $db_conn->error);
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
		_log_db("fail to query database: " . $db_conn->error);
	}
	$domains = array();
	for ($i = 0; $i < mysqli_num_rows($results); ++$i) {
		$row = $results->fetch_row();
		$domains[] = $row[0];
	}
	return $domains;
}

function get_secondary_store_hints($email_address)
{
	$db_conn = get_db_connection();

	$sql_string = "SELECT up.propval_str, u2.primary_email
		FROM users AS u1
		LEFT JOIN secondary_store_hints AS ssh ON u1.id = ssh.primary
		LEFT JOIN users AS u2 ON ssh.secondary = u2.id
		LEFT JOIN user_properties AS up ON u2.id = up.user_id
		WHERE proptag = 0x3001001F AND u1.primary_email = '". $db_conn->real_escape_string($email_address) ."';";

	$results = $db_conn->query($sql_string);
	if (!$results) {
		_log_db("fail to query database: " . $db_conn->error);
	}

	$secondaryStores = array();
	for ($i = 0, $nrResults = mysqli_num_rows($results); $i < $nrResults; ++$i) {
		$row = $results->fetch_row();
		$secondaryStores[] = ['DisplayName' => $row[0], 'SmtpAddress' => $row[1]];
	}
	return $secondaryStores;
}

function get_user_id($account)
{
	$db_conn = get_db_connection();

	$sql_string = "SELECT id FROM users WHERE username='" . $db_conn->real_escape_string($account) . "'";
	$results = $db_conn->query($sql_string);
	if (!$results) {
		die("fail to query database: " . $dbconn->error);
	}
	if (1 != mysqli_num_rows($results)) {
		return false;
	}
	$row = $results->fetch_row();
	return $row[0];
}

?>
