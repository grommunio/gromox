<?php
	if ($_SERVER['REQUEST_METHOD'] === 'POST') {
		session_start();
		if (!isset($_SESSION['USER_HOME'])) {
			die("illegal post method!");
		}
		$n_width = 144;
		$n_height = 144;
		$tsrc = $_SESSION['USER_HOME'] . "/config/portrait.jpg";
		if ($_FILES['userfile']['type'] == "image/gif") {
			$im = imagecreatefromgif($_FILES['userfile']['tmp_name']);
			unlink($_FILES['userfile']['tmp_name']);
		} else if ($_FILES['userfile']['type'] =="image/jpeg"){
			$im = imagecreatefromjpeg($_FILES['userfile']['tmp_name']);
			unlink($_FILES['userfile']['tmp_name']);
		} else if ($_FILES['userfile']['type'] =="image/png") {
			$im = imagecreatefrompng($_FILES['userfile']['tmp_name']);
			unlink($_FILES['userfile']['tmp_name']);
		} else {
			unlink($_FILES['userfile']['tmp_name']);
			die($_FILES['userfile']['type'] . " cannot be processed");
		}
		if (!$im) {
			die ($_FILES['userfile']['tmp_name'] . " cannot be opened");
		}
		$width = imagesx($im);
		$height = imagesy($im);
		$n_height = ($n_width/$width) * $height;
		$newimage = imagecreatetruecolor($n_width, $n_height);
		imagecopyresized($newimage, $im, 0, 0, 0, 0,
			$n_width, $n_height, $width, $height);
		imagejpeg($newimage, $tsrc, 100);
		chmod("$tsrc", 0666);
		session_destroy();
		header("Content-type: image/jpeg");
		imagejpeg($newimage);
		exit(0);
	} else if ($_SERVER['REQUEST_METHOD'] === 'GET') {
		if (!isset($_SERVER['REMOTE_USER'])) {
			header("Status: 401 Unauthorized");
			header("Content-Length: 0");
			header("WWW-Authenticate: Basic realm=" . $_SERVER['SERVER_NAME']);
			exit;
		}
		session_start();
		$_SESSION['USER_HOME'] = $_SERVER['USER_HOME'];
	} else {
		die("invalid request method, must be POST or GET!");
	}
?>

<!doctype html public "-//w3c//dtd html 3.2//en">

<html>

<script language="JavaScript">
<!--
function fxwin() {window.resizeTo(400,160);}
window.onload = fxwin;
window.onresize = fxwin;
//-->
</script>

<head>
<title>Thumbnail photo uploading</title>
</head>

<body >
<FORM ENCTYPE="multipart/form-data" ACTION="thumbnail.php" METHOD=POST>
<INPUT NAME="userfile" TYPE="file" ACCEPT="image/gif, image/jpeg, image/png">
<INPUT TYPE="submit" VALUE="Upload..."></FORM>
</FORM>

</body>

</html>
