<?php

// Do not log errors into stdout
ini_set("display_errors", false);

ini_set("log_errors", true);
error_reporting(E_ERROR);

require_once "../lib/db.php";
require_once "../lib/util.php";

$soap_out;

class ExchangeWebServices { 
	
	function GetUserOofSettingsRequest($Mailbox)
	{
		global $soap_out;
		
		if (!$Mailbox || !$Mailbox->Address) {
			die("E-2008: parameter error in GetUserOofSettingsRequest");
		}
		if (strcasecmp($_SERVER['REMOTE_USER'], $Mailbox->Address) !== 0) {
			die("E-2143: Impersonation not allowed");
		}
		if (!$Mailbox->RoutingType) {
			$Mailbox->RoutingType = "SMTP";
		}
		if (0 == strcasecmp($Mailbox->RoutingType, 'EX')) {
			$uinfo = essdn_to_username($Mailbox->Address);
			if (!$uinfo) {
				die("E-2009: cannot find essdn information");
			}
		} else if (0 == strcasecmp($Mailbox->RoutingType, 'SMTP')) {
			$uinfo = get_user_info_by_name($Mailbox->Address);
			if (!$uinfo) {
				die("E-2010: cannot find email address information");
			}
		} else {
			die("E-2011: unrecognized RoutingType " . $Mailbox->RoutingType);
		}
		date_default_timezone_set($uinfo['timezone']);
		$oofconf = parse_ini_file($uinfo['maildir'] . "/config/autoreply.cfg", false, INI_SCANNER_RAW);
		date_default_timezone_set('UTC');
		if (!$oofconf) {
			$setting['state'] = 'Disabled';
			$setting['external_audience'] = 'None';
			$setting['start_time'] = date("Y-m-dTH:i:s");
			$setting['end_time'] = date("Y-m-dTH:i:s");
		} else {
			switch ($oofconf['OOF_STATE']) {
			case 1:
				$setting['state'] = 'Enabled';
				break;
			case 2:
				$setting['state'] = 'Scheduled';
				break;
			default:
				$setting['state'] = 'Disabled';
				break;
			}
			if (!$oofconf['ALLOW_EXTERNAL_OOF']) {
				if (!$oofconf['EXTERNAL_AUDIENCE']) {
					$setting['external_audience'] = 'All';
				} else {
					$setting['external_audience'] = 'Known';
				}
			} else {
				if (!$oofconf['EXTERNAL_AUDIENCE']) {
					$setting['external_audience'] = 'All';
				} else {
					$setting['external_audience'] = 'Known';
				}
			}
			if (!$oofconf['START_TIME']) {
				$setting['start_time'] = date("Y-m-d\TH:i:s");
			} else {
				$setting['start_time'] = date("Y-m-d\TH:i:s", $oofconf['START_TIME']);
			}
			if (!$oofconf['END_TIME']) {
				$setting['end_time'] = date("Y-m-d\TH:i:s");
			} else {
				$setting['end_time'] = date("Y-m-d\TH:i:s", $oofconf['END_TIME']);
			}
		}
		$content = file_get_contents($uinfo['maildir'] . "/config/internal-reply");
		if ($content) {
			$pos = strpos($content, "\r\n\r\n");
			if ($pos > 0) {
				$setting['internal_reply'] = substr($content, $pos + 4);
			}
		}
		$content = file_get_contents($uinfo['maildir'] . "/config/external-reply");
		if ($content) {
			$pos = strpos($content, "\r\n\r\n");
			if ($pos > 0){
				$setting['external_reply'] = substr($content, $pos + 4);
			}
		}
		$xml = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><soap:Envelope></soap:Envelope>');
		$xml->addAttribute('xmlns:xmlns:soap', 'http://schemas.xmlsoap.org/soap/envelope/');
		$xml->addAttribute('xmlns:xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
		$xml->addAttribute('xmlns:xmlns:xsd', 'http://www.w3.org/2001/XMLSchema');
		$Header = $xml->addChild('soap:soap:Header');
		$ServerVersionInfo = $Header->addChild('t:t:ServerVersionInfo');
		/* 15.00.0847.4040 */
		$ServerVersionInfo->addAttribute('MajorVersion', '15');
		$ServerVersionInfo->addAttribute('MinorVersion', '0');
		$ServerVersionInfo->addAttribute('MajorBuildNumber', '847');
		$ServerVersionInfo->addAttribute('MinorBuildNumber', '4040');
		$ServerVersionInfo->addAttribute('xmlns:xmlns:t', 'http://schemas.microsoft.com/exchange/services/2006/types');
		$Body = $xml->addChild('soap:soap:Body');
		$GetUserOofSettingsResponse = $Body->addChild('GetUserOofSettingsResponse');
		$GetUserOofSettingsResponse->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');
		$ResponseMessage = $GetUserOofSettingsResponse->addChild('ResponseMessage');
		$ResponseMessage->addAttribute('ResponseClass', 'Success');
		$ResponseMessage->addChild('ResponseCode', 'NoError');
		$OofSettings = $GetUserOofSettingsResponse->addChild('OofSettings');
		$OofSettings->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/types');
		$OofSettings->addChild('OofState', $setting['state']);
		$OofSettings->addChild('ExternalAudience', $setting['external_audience']);
		$Duration = $OofSettings->addChild('Duration');
		$Duration->addChild('StartTime', $setting['start_time']);
		$Duration->addChild('EndTime', $setting['end_time']);
		if ($setting['internal_reply']) {
			$InternalReply = $OofSettings->addChild('InternalReply');
			$InternalReply->addChild('Message', $setting['internal_reply']);
		}
		if ($setting['external_reply']) {
			$ExternalReply = $OofSettings->addChild('ExternalReply');
			$ExternalReply->addChild('Message', $setting['external_reply']);
		}
		$GetUserOofSettingsResponse->addChild('AllowExternalOof', "All");
		$soap_out = $xml->asXML();
	}
	
	function SetUserOofSettingsRequest($Mailbox, $UserOofSettings)
	{
		global $soap_out;
		
		if (!$Mailbox || !$Mailbox->Address) {
			die("E-2012: parameter error in SetUserOofSettingsRequest");
		}
		if (strcasecmp($_SERVER['REMOTE_USER'], $Mailbox->Address) !== 0) {
			die("E-2144: Impersonation not allowed");
		}
		if (!$Mailbox->RoutingType) {
			$Mailbox->RoutingType = "SMTP";
		}
		if (0 == strcasecmp($Mailbox->RoutingType, 'EX')) {
			$uinfo = essdn_to_username($Mailbox->Address);
			if (!$uinfo) {
				die("E-2013: cannot find essdn information");
			}
		} else if (0 == strcasecmp($Mailbox->RoutingType, 'SMTP')) {
			$uinfo = get_user_info_by_name($Mailbox->Address);
			if (!$uinfo) {
				die("E-2014: cannot find email address information");
			}
		} else {
			die("E-2015: unrecognized RoutingType " . $Mailbox->RoutingType);
		}
		date_default_timezone_set('UTC');
		if (!$UserOofSettings->OofState) {
			die("E-2016: parameter error in SetUserOofSettingsRequest");
		}
		if (0 == strcasecmp($UserOofSettings->OofState, "Disabled")) {
			$cfgcontent = "OOF_STATE = 0\n";
		} else if (0 == strcasecmp($UserOofSettings->OofState, "Enabled")) {
			$cfgcontent = "OOF_STATE = 1\n";
		} else if (0 == strcasecmp($UserOofSettings->OofState, "Scheduled")) {
			$cfgcontent = "OOF_STATE = 2\n";
		} else {
			die("E-2017: unrecognized OofState " . $UserOofSettings->OofState);
		}
		if (0 == strcasecmp($UserOofSettings->ExternalAudience, "None")) {
			$cfgcontent .= "ALLOW_EXTERNAL_OOF = 0\n";
		} else if (0 == strcasecmp($UserOofSettings->ExternalAudience, "All")) {
			$cfgcontent .= "ALLOW_EXTERNAL_OOF = 1\nEXTERNAL_AUDIENCE = 0\n";
		} else if (0 == strcasecmp($UserOofSettings->ExternalAudience, "Known")) {
			$cfgcontent .= "ALLOW_EXTERNAL_OOF = 1\nEXTERNAL_AUDIENCE = 1\n";
		}
		if ($UserOofSettings->Duration) {
			$cfgcontent .= "START_TIME = " . strtotime($UserOofSettings->Duration->StartTime) . "\n";
			$cfgcontent .= "END_TIME = " . strtotime($UserOofSettings->Duration->EndTime) . "\n";
		}
		file_put_contents($uinfo['maildir']  . "/config/autoreply.cfg", $cfgcontent);
		chmod($uinfo['maildir']  . "/config/autoreply.cfg", 0666);
		if ($UserOofSettings->InternalReply) {
			$mime_content = "Content-Type: text/html;\r\n\tcharset=\"utf-8\""."\r\n\r\n";
			$mime_content .= $UserOofSettings->InternalReply->Message;
			file_put_contents($uinfo['maildir'] . "/config/internal-reply", $mime_content);
			chmod($uinfo['maildir'] . "/config/internal-reply", 0666);
		} else {
			unlink($uinfo['maildir'] . "/config/internal-reply");
		}
		if ($UserOofSettings->ExternalReply) {
			$mime_content = "Content-Type: text/html;\r\n\tcharset=\"utf-8\""."\r\n\r\n";
			$mime_content .= $UserOofSettings->ExternalReply->Message;
			file_put_contents($uinfo['maildir'] . "/config/external-reply", $mime_content);
			chmod($uinfo['maildir'] . "/config/external-reply", 0666);
		} else {
			unlink($uinfo['maildir'] . "/config/external-reply");
		}
		$xml = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><soap:Envelope></soap:Envelope>');
		$xml->addAttribute('xmlns:xmlns:soap', 'http://schemas.xmlsoap.org/soap/envelope/');
		$xml->addAttribute('xmlns:xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
		$xml->addAttribute('xmlns:xmlns:xsd', 'http://www.w3.org/2001/XMLSchema');
		$Header = $xml->addChild('soap:soap:Header');
		$ServerVersionInfo = $Header->addChild('t:t:ServerVersionInfo');
		/* 15.00.0847.4040 */
		$ServerVersionInfo->addAttribute('MajorVersion', '15');
		$ServerVersionInfo->addAttribute('MinorVersion', '0');
		$ServerVersionInfo->addAttribute('MajorBuildNumber', '847');
		$ServerVersionInfo->addAttribute('MinorBuildNumber', '4040');
		$ServerVersionInfo->addAttribute('xmlns:xmlns:t', 'http://schemas.microsoft.com/exchange/services/2006/types');
		$Body = $xml->addChild('soap:soap:Body');
		$SetUserOofSettingsResponse = $Body->addChild('SetUserOofSettingsResponse');
		$ResponseMessage = $SetUserOofSettingsResponse->addChild('ResponseMessage');
		$ResponseMessage->addAttribute('ResponseClass', 'Success');
		$ResponseMessage->addChild('ResponseCode', 'NoError');
		$soap_out = $xml->asXML();
	}
	
	function GetUserAvailabilityRequest($TimeZone, $MailboxDataArray, $Options)
	{
		global $soap_out;
		
		$cookie = 'username=' . $_SERVER['REMOTE_USER'] .
					';starttime=' . $Options->TimeWindow->StartTime .
					';endtime=' .  $Options->TimeWindow->EndTime .
					';bias=' . $TimeZone->Bias .
					';stdbias=' . $TimeZone->StandardTime->Bias .
					';stdtime=' . $TimeZone->StandardTime->Time .
					';stddayorder=' . $TimeZone->StandardTime->DayOrder .
					';stdmonth=' . $TimeZone->StandardTime->Month .
					';stddayofweek=' . $TimeZone->StandardTime->DayOfWeek .
					';dtlbias=' . $TimeZone->DaylightTime->Bias .
					';dtltime=' . $TimeZone->DaylightTime->Time .
					';dtldayorder=' . $TimeZone->DaylightTime->DayOrder .
					';dtlmonth=' . $TimeZone->DaylightTime->Month .
					';dtldayofweek=' . $TimeZone->DaylightTime->DayOfWeek;
		if (isset($TimeZone->StandardTime->Year)) {
			$cookie .= ';stdyear=' . $TimeZone->StandardTime->Year;
		}
		if (isset($TimeZone->DaylightTime->Year)) {
			$cookie .= ';dtlyear=' . $TimeZone->DaylightTime->Year;
		}
		if (!$MailboxDataArray->MailboxData) {
			die("E-2018: parameter error in GetUserAvailabilityRequest");
		}
		if (is_array($MailboxDataArray->MailboxData)) {
			$num = count($MailboxDataArray->MailboxData);
		} else {
			$num = 1;
		}
		$cookie .= ';dirs=' . $num;
		$i = 0;
		$mailboxes = array();
		for ($index=0; $index<$num; $index++) {
			if (is_array($MailboxDataArray->MailboxData)) {
				$Mailbox = $MailboxDataArray->MailboxData[$index];
			} else {
				$Mailbox = $MailboxDataArray->MailboxData;
			}
			if (!$Mailbox->Email || !$Mailbox->Email->Address) {
				die("E-2019: parameter error in GetUserAvailabilityRequest");
			}
			if (!$Mailbox->Email->RoutingType) {
				$Mailbox->Email->RoutingType = "SMTP";
			}
			if (0 == strcasecmp($Mailbox->Email->RoutingType, 'EX')) {
				$uinfo = essdn_to_username($Mailbox->Email->Address);
				if (!$uinfo) {
					$mailboxes[$index] = array('username'=>$Mailbox->Email->Address);
					continue;
				}
			} else if (0 == strcasecmp($Mailbox->Email->RoutingType, 'SMTP')) {
				$uinfo = get_user_info_by_name($Mailbox->Email->Address);
				if (!$uinfo) {
					$mailboxes[$index] = array('username'=>$Mailbox->Email->Address);
					continue;
				}
			} else {
				$mailboxes[$index] = array('username'=>$Mailbox->Email->Address);
				continue;
			}
			$mailboxes[$index] = array('username'=>$Mailbox->Email->Address, 'maildir'=>$uinfo['maildir']);
			$cookie .= ';dir' . $i . '=' . $uinfo['maildir']; 
			$i ++;
		}
		require_once "../lib/conf.php";
		$appconf = get_app_config();
		if (!$appconf['system']['freebusy']) {
			$fb_prog = "/usr/libexec/gromox/freebusy";
		} else {
			$fb_prog = $appconf['system']['freebusy'];
		}
		$descriptorspec = array(
		   0 => array("pipe", "r"),
		   1 => array("pipe", "w"),
		   2 => array("file", "/tmp/ews_err.txt", "a"));
		$process = proc_open($fb_prog, $descriptorspec, $pipes, $cwd, NULL);
		$fbresults = array();
		if (is_resource($process)) {
			fwrite($pipes[0], $cookie);
			fclose($pipes[0]);
			while (($line = fgets($pipes[1])) !== false) {
				$freebusy = json_decode($line, true);
				$fbresults[$freebusy['dir']] = $freebusy;
			}
			proc_close($process);
		}
		$xml = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><soap:Envelope></soap:Envelope>');
		$xml->addAttribute('xmlns:xmlns:soap', 'http://schemas.xmlsoap.org/soap/envelope/');
		$xml->addAttribute('xmlns:xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
		$xml->addAttribute('xmlns:xmlns:xsd', 'http://www.w3.org/2001/XMLSchema');
		$Header = $xml->addChild('soap:soap:Header');
		$ServerVersionInfo = $Header->addChild('t:t:ServerVersionInfo');
		/* 15.00.0847.4040 */
		$ServerVersionInfo->addAttribute('MajorVersion', '15');
		$ServerVersionInfo->addAttribute('MinorVersion', '0');
		$ServerVersionInfo->addAttribute('MajorBuildNumber', '847');
		$ServerVersionInfo->addAttribute('MinorBuildNumber', '4040');
		$ServerVersionInfo->addAttribute('xmlns:xmlns:t', 'http://schemas.microsoft.com/exchange/services/2006/types');
		$Body = $xml->addChild('soap:soap:Body');
		$GetUserAvailabilityResponse = $Body->addChild('GetUserAvailabilityResponse');
		$GetUserAvailabilityResponse->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');
		$FreeBusyResponseArray = $GetUserAvailabilityResponse->addChild('FreeBusyResponseArray');
		$mailbox_num = count($mailboxes);
		for ($i=0; $i<$mailbox_num; $i++) {
			$FreeBusyResponse = $FreeBusyResponseArray->addChild('FreeBusyResponse');
			$ResponseMessage = $FreeBusyResponse->addChild('ResponseMessage');
			$maildir = $mailboxes[$i]['maildir'];
			if (!$maildir || !$fbresults[$maildir]) {
				$ResponseMessage->addAttribute('ResponseClass', 'Error');
				$ResponseMessage->addChild('MessageText', 'Unable to resolve email address ' . $mailboxes[$i]['username']);
				$ResponseMessage->addChild('ResponseCode', 'ErrorMailRecipientNotFound');
				$FreeBusyView = $FreeBusyResponse->addChild('FreeBusyView');
				$FreeBusyViewType = $FreeBusyView->addChild('FreeBusyViewType', 'None');
				$FreeBusyViewType->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/types');
				continue;
			}
			$freebusy = $fbresults[$maildir];
			if (0 == strcasecmp($freebusy['permission'], 'none')) {
				$ResponseMessage->addAttribute('ResponseClass', 'Error');
				$ResponseMessage->addChild('MessageText', 'cannot access ' . $mailboxes[$i]['username'] . "'s freebusy data");
				$ResponseMessage->addChild('ResponseCode', 'InvalidAccessLevel');
				$FreeBusyView = $FreeBusyResponse->addChild('FreeBusyView');
				$FreeBusyViewType = $FreeBusyView->addChild('FreeBusyViewType', 'None');
				$FreeBusyViewType->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/types');
				continue;
			}
			$ResponseMessage->addAttribute('ResponseClass', 'Success');
			$ResponseMessage->addChild('ResponseCode', 'NoError');
			$FreeBusyView = $FreeBusyResponse->addChild('FreeBusyView');
			if (0 == strcasecmp($freebusy['permission'], "detailed")) {
				$FreeBusyViewType = $FreeBusyView->addChild('FreeBusyViewType', 'Detailed');
			} else {
				$FreeBusyViewType = $FreeBusyView->addChild('FreeBusyViewType', 'FreeBusy');
			}
			$FreeBusyViewType->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/types');
			$CalendarEventArray = $FreeBusyView->addChild('CalendarEventArray');
			foreach ($freebusy['events'] as $event) {
				$CalendarEvent = $CalendarEventArray->addChild('CalendarEvent');
				$CalendarEvent->addChild('StartTime', $event['StartTime']);
				$CalendarEvent->addChild('EndTime', $event['EndTime']);
				$CalendarEvent->addChild('BusyType', $event['BusyType']);
				if (0 == strcasecmp($freebusy['permission'], "detailed")) {
					$CalendarEventDetails = $CalendarEvent->addChild('CalendarEventDetails');
					$CalendarEventDetails->addChild('Subject', base64_decode($event['Subject']));
					$CalendarEventDetails->addChild('Location', base64_decode($event['Location']));
					if ($event['IsMeeting']) {
						$CalendarEventDetails->addChild('IsMeeting', 'true');
					} else {
						$CalendarEventDetails->addChild('IsMeeting', 'false');
					}
					if ($event['IsRecurring']) {
						$CalendarEventDetails->addChild('IsRecurring', 'true');
					} else {
						$CalendarEventDetails->addChild('IsRecurring', 'false');
					}
					if ($event['IsException']) {
						$CalendarEventDetails->addChild('IsException', 'true');
					} else {
						$CalendarEventDetails->addChild('IsException', 'false');
					}
					if ($event['IsReminderSet']) {
						$CalendarEventDetails->addChild('IsReminderSet', 'true');
					} else {
						$CalendarEventDetails->addChild('IsReminderSet', 'false');
					}
					if ($event['IsPrivate']) {
						$CalendarEventDetails->addChild('IsPrivate', 'true');
					} else {
						$CalendarEventDetails->addChild('IsPrivate', 'false');
					}
				}
			}	
		}
		$soap_out = $xml->asXML();
	}

	function GetMailTips($SendingAs, $Recipients, $MailTipsRequested) {
		global $soap_out;
		error_log("GetMailTips()" . print_r($SendingAs, 1) . print_r($Recipients, 1) . print_r($MailTipsRequested, 1));

		$xml = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><soap:Envelope></soap:Envelope>');
		$xml->addAttribute('xmlns:xmlns:soap', 'http://schemas.xmlsoap.org/soap/envelope/');
		$xml->addAttribute('xmlns:xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
		$xml->addAttribute('xmlns:xmlns:xsd', 'http://www.w3.org/2001/XMLSchema');
		$Header = $xml->addChild('soap:soap:Header');
		$ServerVersionInfo = $Header->addChild('t:t:ServerVersionInfo');
		/* 15.00.0847.4040 */
		$ServerVersionInfo->addAttribute('MajorVersion', '15');
		$ServerVersionInfo->addAttribute('MinorVersion', '0');
		$ServerVersionInfo->addAttribute('MajorBuildNumber', '847');
		$ServerVersionInfo->addAttribute('MinorBuildNumber', '4040');
		$ServerVersionInfo->addAttribute('xmlns:xmlns:t', 'http://schemas.microsoft.com/exchange/services/2006/types');
		$Body = $xml->addChild('soap:soap:Body');

		$GetMailTipsResponse = $Body->addChild('GetMailTipsResponse');
		$GetMailTipsResponse->addAttribute('ResponseClass', 'Success');
		$GetMailTipsResponse->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');
		$GetMailTipsResponse->addChild('ResponseCode', 'NoError');
		$ResponseMessages = $GetMailTipsResponse->addChild('ResponseMessages');
		$MailTipsResponseMessageType = $ResponseMessages->addChild('MailTipsResponseMessageType');
		$MailTipsResponseMessageType->addAttribute('ResponseClass', 'Success');
		$MailTipsResponseMessageType->addChild('ResponseCode', 'NoError');

		$MailTips = $MailTipsResponseMessageType->addChild('m:MailTips');
		$MailTips->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');

		$RecipientAddress= $MailTips->addChild('t:RecipientAddress');
		$RecipientAddress->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');
		$RecipientAddress->addChild('t:Name', "");
		$RecipientAddress->addChild('t:EmailAddress', $Recipients->Mailbox->EmailAddress);
		$RecipientAddress->addChild('t:RoutingType', $Recipients->Mailbox->RoutingType);

		$PendingMailTips= $MailTips->addChild('t:PendingMailTips');
		$PendingMailTips->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');

		#$CustomMailTip= $MailTips->addChild('t:CustomMailTip', "A custom message regarding this recipient.");
		#$CustomMailTip->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');

		# TODO implement other requested types
		# OutOfOfficeMessage MailboxFullStatus CustomMailTip ExternalMemberCount TotalMemberCount MaxMessageSize DeliveryRestriction ModerationStatus InvalidRecipient
		#if (in_array('OutOfOfficeMessage', $MailTipsRequestedArray)) {
		#}

		error_log($xml->asXML(), 0);
		$soap_out = $xml->asXML();

	}

	function GetServiceConfiguration($ActingAs, $RequestedConfiguration) {
		global $soap_out;
		error_log("GetServiceConfiguration()" . print_r($ActingAs, 1). print_r($RequestedConfiguration, 1));

		$xml = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><soap:Envelope></soap:Envelope>');
		$xml->addAttribute('xmlns:xmlns:soap', 'http://schemas.xmlsoap.org/soap/envelope/');
		$xml->addAttribute('xmlns:xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
		$xml->addAttribute('xmlns:xmlns:xsd', 'http://www.w3.org/2001/XMLSchema');
		$Header = $xml->addChild('soap:soap:Header');
		$ServerVersionInfo = $Header->addChild('t:t:ServerVersionInfo');
		/* 15.00.0847.4040 */
		$ServerVersionInfo->addAttribute('MajorVersion', '15');
		$ServerVersionInfo->addAttribute('MinorVersion', '0');
		$ServerVersionInfo->addAttribute('MajorBuildNumber', '847');
		$ServerVersionInfo->addAttribute('MinorBuildNumber', '4040');
		$ServerVersionInfo->addAttribute('xmlns:xmlns:t', 'http://schemas.microsoft.com/exchange/services/2006/types');
		$Body = $xml->addChild('soap:soap:Body');

		$GetServiceConfigurationResponse = $Body->addChild('GetServiceConfigurationResponse');
		$GetServiceConfigurationResponse->addAttribute('ResponseClass', 'Success');
		$GetServiceConfigurationResponse->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');
		$GetServiceConfigurationResponse->addChild('ResponseCode', 'NoError');
		$ResponseMessages = $GetServiceConfigurationResponse->addChild('ResponseMessages');
		$ServiceConfigurationResponseMessageType = $ResponseMessages->addChild('ServiceConfigurationResponseMessageType');
		$ServiceConfigurationResponseMessageType->addAttribute('ResponseClass', 'Success');
		$ServiceConfigurationResponseMessageType->addChild('ResponseCode', 'NoError');

		$MailTipsConfiguration = $ServiceConfigurationResponseMessageType->addChild('m:MailTipsConfiguration');
		$MailTipsConfiguration->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');
		$MailTipsEnabled= $MailTipsConfiguration->addChild('t:MailTipsEnabled', 'false');
		$MailTipsEnabled->addAttribute('xmlns', 'http://schemas.microsoft.com/exchange/services/2006/messages');

		error_log($xml->asXML(), 0);
		$soap_out = $xml->asXML();
	}

};

if (!isset($_SERVER['REMOTE_USER'])) {
	header("Status: 401 Unauthorized");
	header("Content-Length: 0");
	header("WWW-Authenticate: Basic realm=" . $_SERVER['SERVER_NAME']);
	exit;
}

$server = new SoapServer(NULL, array('uri' => $_SERVER['PHP_SELF']));

$server->setClass('ExchangeWebServices'); 
$server->addFunction(SOAP_FUNCTIONS_ALL);

ob_start();
# If a client requests a function we do not know (e.g. GetAppManifests
# is one), this will throw an exception and the entire HTTP request dies
# with 5xx.
$server->handle();
ob_end_clean();

error_log("EWS response:\n" . $soap_out, 0);
$len=strlen($soap_out);
header("Content-Length: ".$len);
echo $soap_out;
?>