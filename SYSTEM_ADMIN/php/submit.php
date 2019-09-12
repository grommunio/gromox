<?php
	define('PR_MESSAGE_FLAGS',				0x0E070003);
	define('PR_DEFERRED_DELIVERY_TIME',		0x000F0040);
	define('PR_DEFERRED_SEND_TIME',			0x3FEF0040);
	define('PR_DEFERRED_SEND_UNIT',			0x3FEC0003);
	define('MSGFLAG_SUBMIT',    0x00000004);

	if ($argc < 3) {
        printf("Usage: %s account exmdb_id\n", $argv[0]);
        exit();
	}
	require_once "db.php";
	$user_id = get_user_id($argv[1]);
	if (empty($user_id)) {
		die("cannot find " . $argv[1] . "'s information from database"); 
	}
	$loc_string = sprintf("/exmdb=3:%d:%x", $user_id, $argv[2]);
	// append a null terminate character for C
	$loc_string .= hex2bin('00');
	$_SERVER['REMOTE_USER'] = $argv[1];
	try {
		$session = mapi_logon_ex($argv[1], null, 0);
	} catch (Exception  $e) {
		die("fail to log on the " . $argv[1] . "'s store");
	}
	try {
		$message = mapi_openentry($session, $loc_string);
	} catch (Exception  $e) {
		die("fail to open message " . $argv[2]);
	}
	$props = mapi_getprops($message, array(PR_MESSAGE_FLAGS));
	if (empty($props[PR_MESSAGE_FLAGS])) {
		die("cannot get PR_MESSAGE_FLAGS from message object");
	}
	if (0 == (MSGFLAG_SUBMIT & $props[PR_MESSAGE_FLAGS])) {
		die("message " . $argv[2] . " was not submitted");
	}
	mapi_message_submitmessage($message);
	exit("message " . $argv[2] . " has been submitted successfully");
?>