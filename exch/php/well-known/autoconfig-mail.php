<?php

require_once "../lib/conf.php";
require_once "../lib/db.php";
require_once "../lib/util.php";

# Get the lookup email address from query string
parse_str(filter_input(INPUT_SERVER, 'QUERY_STRING'), $query_strings);
if (!isset($query_strings['emailaddress'])) {
	http_response_code(400);
	die();
}

# return the valid login for the user (main email)
# TODO lookup for aliases
$user_name = $query_strings['emailaddress'];

# hostname to connect to
$host_name = get_default_hostname();

# parameter documentation:
#   https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
$xml = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><clientConfig />');
$xml->addAttribute('version', '1.1');
$provider = $xml->addChild('emailProvider');
$provider->addAttribute('id', $host_name);
foreach (get_domains() as $domain) {
	$provider->addChild('domain', $domain);
}
$provider->addChild('displayName', 'Gromox Mail');
$provider->addChild('displayShortName', 'Gromox');

$imap = $provider->addChild('incomingServer');
$imap->addAttribute('type', 'imap');
$imap->addChild('hostname', $host_name);
$imap->addChild('port', '143');
$imap->addChild('socketType', 'plain');
$imap->addChild('authentication', 'password-cleartext');
$imap->addChild('username', $user_name);

$smtp = $provider->addChild('outgoingServer');
$smtp->addAttribute('type', 'smtp');
$smtp->addChild('hostname', $host_name);
$smtp->addChild('port', '25');
$smtp->addChild('socketType', 'plain');
$smtp->addChild('authentication', 'password-cleartext');
$smtp->addChild('username', $user_name);

header("Content-Type: text/xml; charset=utf-8");
print $xml->asXML();

?>