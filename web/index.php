<?php
if (empty($_FILES['upload'])) {
	echo '
<!DOCTYPE html>
<html>

	<head>
		<meta charset="utf-8"/>
		<title>Drag and Drop PCAP Injector</title>

		<!-- Google web fonts -->
		<link href="http://fonts.googleapis.com/css?family=PT+Sans+Narrow:400,700" rel="stylesheet" />

		<!-- The main CSS file -->
		<link href="assets/css/style.css" rel="stylesheet" />
	</head>

	<body>

		<form id="upload" method="post" action="/" enctype="multipart/form-data">
			<div id="drop">
				Upload Pcap	
				<br />
				<br />
				<input type="file" name="upload" value="Browse"></input>
				<input type="submit" value="Upload"></input>
			</div>
		</form>

            </div>
	</body>
</html>';
} else {
        header('Content-Type: text/javascript');
	$allowed = array('pcap');
        
	$extension = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);

        if(!in_array(strtolower($extension), $allowed)){
                echo '{"status":"error"}';
                exit;
        }

        chdir('../bin');
        if ($output = shell_exec('./optimus.pl -g -j -p '.$_FILES['upload']['tmp_name'])) {
                echo $output;
                exit;
        } else {
                echo '{"status":"error"}';
                echo "ERROR";
                exit;
        }

        # upload pcap files using curl
        # curl -F 'upload=@/path/to/pcap' http://localhost/optimus/test.php
}
?>
