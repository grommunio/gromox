<?php

require_once "../lib/db.php";
require_once "../lib/util.php";

define("RESPONSE_XMLNS", "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006");
define("RESPONSE_OUTLOOK_XMLNS", "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a");
define("SERVER_VERSION", "73C0834F"); //15.00.0847.4040
define("RESPONSE_MOBILE_XMLNS", "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006");


/*
request list like below:

<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
	<Request>
		<EMailAddress>user@contoso.com</EMailAddress>
		<LegacyDN>/o=contoso/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=user
		<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
	</Request>
</Autodiscover>
*/

if (!isset($_SERVER['HTTPS'])) {
	require_once "../lib/conf.php";
	header("Location: https://" . get_default_hostname() . "/Autodiscover/Autodiscover.xml");
	exit;
}

if (0 != strcasecmp($_SERVER['REQUEST_METHOD'], "POST")) {
	die("invalid request method, must be POST!");
}

$xml_in = file_get_contents("php://input");
$xml_request = simplexml_load_string($xml_in);

if (0 != strcasecmp($xml_request->getName(), "Autodiscover")) {
	die("invalid request xml root, should be Autodiscover");
}

$email_address = $xml_request->Request->EMailAddress;
if (!isset($email_address)) {
	die("cannot find Request/EMailAddress in xml request");
}
if (!strpos($email_address, '@')) {
	die("format error with Request/EMailAddress in xml request");
}

if ('public.folder.root' == substr($email_address, 0, strpos($email_address, "@"))) {
	$domain = substr($email_address, strpos($email_address, "@") + 1);
	$dinfo = get_domain_info_by_name($domain);
	if (!$dinfo) {
		die("cannot find domain information");
	}
	$Autodiscover = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><Autodiscover></Autodiscover>');
	$Autodiscover->addAttribute('xmlns', RESPONSE_XMLNS);
	$Response = $Autodiscover->addChild('Response');
	$Response->addAttribute('xmlns', RESPONSE_OUTLOOK_XMLNS);
	$User = $Response->addChild('User');
	$User->addChild('AutoDiscoverSMTPAddress', 'public.folder.root@' . $domain);
	$User->addChild('DisplayName', 'Public Folder');
	$User->addChild('LegacyDN', publicfolder_to_essdn($dinfo));
	$User->addChild('DelpoymentId', get_domain_server_guid($dinfo));
	$Account = $Response->addChild('Account');
	$Account->addChild('AccountType', 'email');
	$Account->addChild('Action', 'settings');
	$Protocol = $Account->addChild('Protocol');
	$host_name = get_default_hostname();
	$server_name = get_domain_server_guid($dinfo) . '@' . $dinfo['domain'];
	if (get_mapihttp_supported() &&
		0 == strncasecmp($_SERVER['HTTP_USER_AGENT'], "Microsoft Office/", 17)
		&& floatval(substr($_SERVER['HTTP_USER_AGENT'], 17)) >= 16) {
		$Protocol->addChild('Type', 'EXHTTP');
		$Protocol->addChild('Server', get_http_proxy($dinfo['homedir'], $host_name));
		$Protocol->addChild('SSL', 'On');
		$Protocol->addChild('CertPrincipalName', 'None');
		$Protocol->addChild('AuthPackage', 'basic');
		$Protocol->addChild('ServerExclusiveConnect', 'on');
		$Protocol = $Account->addChild('Protocol');
		$Protocol->addAttribute('Type', 'mapiHttp');
		$Protocol->addAttribute('Version', '1');
		$MailStore = $Protocol->addChild('MailStore');
		$MailStore->addChild('InternalUrl', 'https://' . get_http_proxy($dinfo['homedir'], $host_name) . "/mapi/emsmdb/?MailboxId=" . $server_name);
		$MailStore->addChild('ExternalUrl', 'https://' . get_http_proxy($dinfo['homedir'], $host_name) . "/mapi/emsmdb/?MailboxId=" . $server_name);
		$AddressBook = $Protocol->addChild('AddressBook');
		$AddressBook->addChild('InternalUrl', 'https://' . get_http_proxy($dinfo['homedir'], $host_name) ."/mapi/nspi/?MailboxId=" . $server_name);
		$AddressBook->addChild('ExternalUrl', 'https://' . get_http_proxy($dinfo['homedir'], $host_name) ."/mapi/nspi/?MailboxId=" . $server_name);
	} else {
		$Protocol->addChild('Type', 'EXCH');
		$Protocol->addChild('Server', $server_name);
		$Protocol->addChild('ServerVersion', SERVER_VERSION);
		$Protocol->addChild('ServerDN', get_server_dn($server_name));
		$Protocol->addChild('MdbDN', get_mdb_dn($server_name));
		if (0 == strncasecmp($_SERVER['HTTP_USER_AGENT'], "Microsoft Office/", 17)
			&& floatval(substr($_SERVER['HTTP_USER_AGENT'], 17)) >= 15) {
			$Protocol->addChild('AuthPackage', 'anonymous');
		} else {
			$Protocol->addChild('AuthPackage', 'ntlm');
		}
		$Protocol->addChild('ServerExclusiveConnect', 'off');
		$Protocol = $Account->addChild('Protocol');
		$Protocol->addChild('Type', 'EXPR');
		$Protocol->addChild('Server', get_http_proxy($dinfo['homedir'], $host_name));
		$Protocol->addChild('SSL', 'On');
		$Protocol->addChild('CertPrincipalName', 'None');
		$Protocol->addChild('AuthPackage', 'basic');
		$Protocol->addChild('ServerExclusiveConnect', 'on');
	}
} else {
	if (!isset($_SERVER['REMOTE_USER'])) {
		header("Status: 401 Unauthorized");
		header("Content-Length: 0");
		header("WWW-Authenticate: Basic realm=" . $_SERVER['SERVER_NAME']);
		exit;
	}
	
	if (isset($xml_request->Request->AcceptableResponseSchema) &&
		0 == strcasecmp($xml_request->Request->AcceptableResponseSchema,
		RESPONSE_MOBILE_XMLNS)) {
		/* ActiveSync Autodiscover */
		$uinfo = get_user_info_by_name($email_address);
		if (!$uinfo) {
			die("cannot find email address information");
		}
		
		$Autodiscover = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><Autodiscover></Autodiscover>');
		$Autodiscover->addAttribute('xmlns', RESPONSE_XMLNS);
		$Response = $Autodiscover->addChild('Response');
		$Response->addAttribute('xmlns', RESPONSE_MOBILE_XMLNS);
		$Response->addChild('Culture', 'en:us');
		$User = $Response->addChild('User');
		$host_name = get_default_hostname();
		$server_url = "https://" . get_http_proxy($uinfo['maildir'], $host_name) . "/Microsoft-Server-ActiveSync";
		$User->addChild('DisplayName', $uinfo['real_name']);
		$User->addChild('EMailAddress', $uinfo['username']);
		$Action = $Response->addChild('Action');
		$Settings = $Action->addChild('Settings');
		$Server = $Settings->addChild('Server');
		$Server->addChild('Type', 'MobileSync');
		$Server->addChild('Url', $server_url);
		$Server->addChild('Name', $server_url);
		
	} else {
		$legacy_dn = $xml_request->Request->LegacyDN;
		if ($legacy_dn) {
			$uinfo = essdn_to_username($legacy_dn);
			if (!$uinfo) {
				die("cannot find essdn information");
			}
		} else {
			$uinfo = get_user_info_by_name($email_address);
			if (!$uinfo) {
				die("cannot find email address information");
			}
		}
		
		$Autodiscover = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><Autodiscover></Autodiscover>');
		$Autodiscover->addAttribute('xmlns', RESPONSE_XMLNS);
		$Response = $Autodiscover->addChild('Response');
		$Response->addAttribute('xmlns', RESPONSE_OUTLOOK_XMLNS);
		$User = $Response->addChild('User');
		$User->addChild('AutoDiscoverSMTPAddress', $uinfo['username']);
		$User->addChild('DisplayName', $uinfo['real_name']);
		$User->addChild('LegacyDN', username_to_essdn($uinfo));
		$User->addChild('EMailAddress', $uinfo['username']);
		$User->addChild('DelpoymentId', get_user_server_guid($uinfo));
		$Account = $Response->addChild('Account');
		$Account->addChild('AccountType', 'email');
		$Account->addChild('Action', 'settings');
		$Protocol = $Account->addChild('Protocol');
		$host_name = get_default_hostname();
		$server_name = get_user_server_guid($uinfo) . '@' . $uinfo['domain'];
		if (get_mapihttp_supported() &&
			0 == strncasecmp($_SERVER['HTTP_USER_AGENT'], "Microsoft Office/", 17)
			&& floatval(substr($_SERVER['HTTP_USER_AGENT'], 17)) >= 16) {
			$Protocol->addChild('Type', 'EXHTTP');
			$Protocol->addChild('Server', get_http_proxy($uinfo['maildir'], $host_name));
			$Protocol->addChild('SSL', 'On');
			$Protocol->addChild('CertPrincipalName', 'None');
			$Protocol->addChild('AuthPackage', 'basic');
			$Protocol->addChild('ASUrl', 'https://' . $host_name . '/EWS/Exchange.asmx');
			$Protocol->addChild('EwsUrl', 'https://' . $host_name . '/EWS/Exchange.asmx');
			$Protocol->addChild('EmwsUrl', 'https://' . $host_name . '/EWS/Exchange.asmx');
			$Protocol->addChild('EcpUrl', 'https://' . $host_name . '/ews/');
			$Protocol->addChild('EcpUrl-photo', 'thumbnail.php');
			$Protocol->addChild('ServerExclusiveConnect', 'on');
			$Protocol = $Account->addChild('Protocol');
			$Protocol->addAttribute('Type', 'mapiHttp');
			$Protocol->addAttribute('Version', '1');
			$MailStore = $Protocol->addChild('MailStore');
			$MailStore->addChild('InternalUrl', 'https://' . get_http_proxy($uinfo['maildir'], $host_name) . "/mapi/emsmdb/?MailboxId=" . $server_name);
			$MailStore->addChild('ExternalUrl', 'https://' . get_http_proxy($uinfo['maildir'], $host_name) . "/mapi/emsmdb/?MailboxId=" . $server_name);
			$AddressBook = $Protocol->addChild('AddressBook');
			$AddressBook->addChild('InternalUrl', 'https://' . get_http_proxy($uinfo['maildir'], $host_name) ."/mapi/nspi/?MailboxId=" . $server_name);
			$AddressBook->addChild('ExternalUrl', 'https://' . get_http_proxy($uinfo['maildir'], $host_name) ."/mapi/nspi/?MailboxId=" . $server_name);
		} else {
			$Protocol->addChild('Type', 'EXCH');
			$Protocol->addChild('Server', $server_name);
			$Protocol->addChild('ServerVersion', SERVER_VERSION);
			$Protocol->addChild('ServerDN', get_server_dn($server_name));
			$Protocol->addChild('MdbDN', get_mdb_dn($server_name));
			$Protocol->addChild('OOFUrl', 'https://' . $host_name . '/EWS/Exchange.asmx');
			$Protocol->addChild('OABUrl', 'https://' . $host_name . '/OAB/');
			if (0 == strncasecmp($_SERVER['HTTP_USER_AGENT'], "Microsoft Office/", 17)
				&& floatval(substr($_SERVER['HTTP_USER_AGENT'], 17)) >= 15) {
				$Protocol->addChild('AuthPackage', 'anonymous');
			} else {
				$Protocol->addChild('AuthPackage', 'ntlm');
			}
			$Protocol->addChild('PublicFolderServer', get_default_hostname());
			$Protocol->addChild('ASUrl', 'https://' . $host_name . '/EWS/Exchange.asmx');
			$Protocol->addChild('EwsUrl', 'https://' . $host_name . '/EWS/Exchange.asmx');
			$Protocol->addChild('EmwsUrl', 'https://' . $host_name . '/EWS/Exchange.asmx');
			$Protocol->addChild('EcpUrl', 'https://' . $host_name . '/ews/');
			$Protocol->addChild('EcpUrl-photo', 'thumbnail.php');
			$Protocol->addChild('ServerExclusiveConnect', 'off');
			$Protocol = $Account->addChild('Protocol');
			$Protocol->addChild('Type', 'EXPR');
			$Protocol->addChild('Server', get_http_proxy($uinfo['maildir'], $host_name));
			$Protocol->addChild('SSL', 'On');
			$Protocol->addChild('CertPrincipalName', 'None');
			$Protocol->addChild('AuthPackage', 'basic');
			$Protocol->addChild('ServerExclusiveConnect', 'on');
		}
		$publicfolder = $Account->addChild('PublicFolderInformation');
		$publicfolder->addChild('SmtpAddress', 'public.folder.root' . substr($email_address, strpos($email_address, "@")));
	}
}
header("Content-Type: text/xml; charset=utf-8");

print $Autodiscover->asXML();

exit;

?>