<?php







$action = $_GET["action"];

if($action == "scan"){

	$url = $_POST['url'];

	if(preg_match("#;|\||&|%#", $url)){ die("Bad, very bad, this characters are not accepted: ; | & %");}
	$str =  "./uniscan.pl -b -u " . $url;

	foreach ($_POST['options'] as $key => $value) {
		if(preg_match("#;|\||&|%#", $value)){
			die("Bad, very bad, this characters are not accepted: ; | & %");
		}
		$str .= $value;
	}

        $str .= " > /dev/null &";
	$a = shell_exec($str);
	sleep(10);
	header('Location: report/uniscan.html');

}
else if($action == "search"){
	$google = $_POST["google"];
	$bing = $_POST["bing"];
	if(preg_match("#;|\||&|%#", $google)){ die("Bad, very bad, this characters are not accepted: ; | & %");}
	if(preg_match("#;|\||&|%#", $bing)){ die("Bad, very bad, this characters are not accepted: ; | & %");}
	$cmd = "perl uniscan.pl ";
	if($bing !== ""){
	    $cmd = $cmd . " -i $bing";
	}
	
	if($google !== ""){
	    $cmd = $cmd . " -o $google";
	}
	echo "<pre>";
	system($cmd);
	echo "</pre>";
	
}
else{
?> 

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Uniscan Web Client</title>
<link href="report/css.css" rel="stylesheet" />
</head>

<body>
<div id="div1" style="border:dotted">
  <p><center>Search Engine</center></p>
  <form action="index.php?action=search" method="post">
  <p>Google Search: <input type="text" name="google" /></p>
  <p>Bing Search:<input type="text" name="bing" /></p>
  <p><input type="submit" value="Send" /><input type="reset" value="Reset"></form></p>
</div>

<div id="div2" style="border:dotted">
<p><center>Scan Options</center></p>
<form action="index.php?action=scan" method="post">
<input type="checkbox" name="options[]" value=" -q" checked="checked" /> Directory Check<br>
<input type="checkbox" name="options[]" value=" -w" checked="checked" /> File Check<br>
<input type="checkbox" name="options[]" value=" -e" checked="checked" /> /robots.txt Check<br>
<input type="checkbox" name="options[]" value=" -d" checked="checked" /> Dynamic Tests<br>
<input type="checkbox" name="options[]" value=" -s" checked="checked" /> Static Tests<br>
<input type="checkbox" name="options[]" value=" -r" checked="checked" /> Stress Tests<br>
<input type="checkbox" name="options[]" value=" -g" checked="checked" /> Web Server Information<br>
<input type="checkbox" name="options[]" value=" -j" checked="checked" /> Server Information<br><br>

</div>

<div id="div3">Target:<br>
URL: <input type="text" name="url" value="http://www.site.com/" /><br><br><br><br><br><br><br><br><br>	
<input type="submit" value="Start Scan" />
<input type="reset" value="Reset">
</form>
</div>
</body>
</html>



<?php 
}
?>
