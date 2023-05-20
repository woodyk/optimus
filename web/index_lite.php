<?php
if (empty($_FILES['upload'])) {
	echo '
	<!DOCTYPE html>
	<html>
	<head>
	<title>Process PCAP</title>
	</head>
	<body>

	<form enctype="multipart/form-data" action="index_lite.php" method="POST">
	<input type="file" name="upload"></input>
	<input type="submit" value="Upload"></input>
	</form>
	</body>
	</html>';
} else {
	header('Content-Type: text/javascript');
	$path = "uploads/";
	$path = $path . basename( $_FILES['upload']['name']);

	chdir('../bin');
	if ($output = shell_exec('./optimus.pl -g -j -p '.$_FILES['upload']['tmp_name'])) {
		echo $output;
		exit;
	} else {
		echo "ERROR";
		exit;
	}

	# upload pcap files using curl
	# curl -F 'upload=@/path/to/pcap' http://localhost/optimus/test.php
}
?>
