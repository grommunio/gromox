<?php

header("Content-Type: text/xml; charset=utf-8");

$oab = new SimpleXMLElement('<?xml version="1.0" encoding="utf-8"?><OAB></OAB>');

print $oab->asXML();
exit;

?>