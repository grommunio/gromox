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
	require_once __DIR__ . "/conf.php";
	require_once __DIR__ . "/db.php";
	$user_id = get_user_id($argv[1]);
	if (empty($user_id)) {
		die("cannot find " . $argv[1] . "'s information from database"); 
	}
	$msgid = intval($argv[2], 0);
	$loc_string = sprintf("/exmdb=3:%d:%x", $user_id, $msgid);
	// append a null terminate character for C
	$loc_string .= hex2bin('00');
	$_SERVER['REMOTE_USER'] = $argv[1];
	try {
		$session = mapi_logon_np($argv[1], 0);
	} catch (Exception  $e) {
		die("fail to log on the " . $argv[1] . "'s store");
	}
	try {
		$message = mapi_openentry($session, $loc_string);
	} catch (Exception  $e) {
		die("Failed to open message " . $argv[2]);
	}
	$props = mapi_getprops($message, array(PR_MESSAGE_FLAGS));
	if (empty($props[PR_MESSAGE_FLAGS])) {
		die("cannot get PR_MESSAGE_FLAGS from message object");
	}
	if (!($props[PR_MESSAGE_FLAGS] & MSGFLAG_SUBMIT)) {
		fwrite(STDERR, "$argv[2]: submit-init\n");
		#
		# MSGFLAG_SUBMIT not set. submitmessage() will start delayed
		# delivery timers (if desired), or send right away and purge.
		#
	} else {
		fwrite(STDERR, "$argv[2]: submit-now\n");
		#
		# MSGFLAG_SUBMIT is set. This means, now that we are called
		# (possibly a second time) that the timer has expired.
		# Send immediately.
		#
	}
	mapi_message_submitmessage($message);
	exit("message " . $argv[2] . " has been submitted successfully");
?>
