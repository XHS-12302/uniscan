package Uniscan::Crawler;

use Moose;
use Uniscan::Http;
use threads;
use threads::shared;
use Thread::Queue;
use strict;
use Uniscan::Configure;
use Uniscan::Functions;

our %files	: shared = ( );
our @list	: shared = ( );
our %forms	: shared = ( );
our %urls	: shared = ( );
our $q		: shared = ( );
our $p		: shared = 0;
our $u		: shared = 0;
our $url;
our @url_list = ( );
our $func = Uniscan::Functions->new();
our %conf = ( );
our $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
our %email : shared = ( );


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
	while ($content =~  m/<input(.+?)>/gi){
		my $inp = $1;
		if($inp =~ /name/i){
			$inp =~ m/name *= *"(.+?)"/gi;
			push(@input, $1);
		}
	}
	return @input;
}





##############################################
#  Function get_extension
#  this function return the extension of a file
#
#  Param: $path/to/file
#  Return: $extension of file
##############################################

sub get_extension(){
	my  $file = shift;
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
#  Function add_form
#  when the crawler identifies a form, this 
#  function is called to add the form and the 
#  inputs in a hash to be tested after
#
#  Param: $url, $content of this url
#  Return: nothing
##############################################


sub add_form(){
	my ($site, $content) = @_;
	my @form = ();
	my $url2;
	$content =~ s/\n//g;
	while($content =~ /<form(.+)<\/form>/gi){
		my $cont = $1;
		if($cont =~/method *=/i && $cont =~/action *=/i)
		{
			$cont =~ /action *= *"(.+?)"/i;
			my $action = $1;
			return if(!$action);
			if($action =~ /^\//){
				$action = $func->get_url($site) . $action;
			}
			elsif($action =~ /^https?:\/\//){
				return if($action !~ $func->get_url($site))
			}
			else{
				my $x = 0;
				while($action =~ m/\.\.\//g){
					$x++;
				}
				my $i;
				$url2 = substr($site, 0, rindex($site, '/')+1);
				for($i=0;$i<$x;$i++){
					$action = substr($action, 3, length($action));
					$url2 = substr($url2, 0, rindex($url2, '/'));
					$url2 = substr($url2, 0, rindex($url2, '/')+1);
				}
				$action = $url2 . $action;
			}
			$cont =~ m/method *= *"(.+?)"/gi;
			my $method = $1;
			return if(!$method);

			my @inputs = &get_input($cont);

			if($method =~ /get/i ){
				$url2 = $action . '?';
				foreach my $var (@inputs){
					$url2 .= '&'.$var .'=123' if($var);
				}
		
				my $fil = $func->get_file($url2);
				my $ext = &get_extension($fil);
				if($conf{'extensions'} !~/$ext/){
					$files{$fil}++;
					if($files{$fil} <= $conf{'variation'}){
						push(@list, $url2) if($url2 !~/\s|"|'|:/);
					}
				}
			}
			else {
				my $data;
				foreach my $var (@inputs){
					$data .='&'.$var.'=123' if($var);
				}
				if(!$forms{$action}){
					if($data){
						$forms{$action} = $data  if($action !~/\s|"|'|:/);
						$q->enqueue($action."#".$data) if($action !~/\s|"|'|:/);
					}
				}
			}
		}
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
	if($base !~ /\/\/$/){
		my @lst = ();
		my @ERs = (	"href=\"(.+)\"", 
				"href='(.+)'", 
				"location.href='(.+)'",
				"src='(.+)'",
				"src=\"(.+)\"",
				"location.href=\"(.+)\"", 
				"<meta.*content=\"?.*;URL=(.+)\"?.*?>"
			);
				
		my $h = Uniscan::Http->new();
		my $data;
		my $result;
		if($base =~/#/){
			($base, $data) = split('#', $base);
			$result = $h->POST($base, $data);
		}
		else{
			$result = $h->GET($base);
		}


		if($result){

			while($result =~m/([\w\-\_\.]+\@[\w\d\-]+\.\w+[\.[a-z]+]*)/g){
				$email{$1}++;
			}

			if($result =~ m/<form/i){
				&add_form($base, $result);
			}

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
							$link = $url . $link;
						}
						else{
							my $u = $base;
							if($u =~ /http:\/\//){
								$u =~s/http:\/\///g;
								$u = substr($u, 0, rindex($u, '/')+1);
								if($link =~/^\.\.\//){
									while($link =~ /^\.\.\//){
										$link = substr($link, 3, length($link));
										$u = substr($u, 0, rindex($u, '/'));
										$u = substr($u, 0, rindex($u, '/')+1);
									}
									$link = "http://" . $u . $link;
								}
								else{
									$u = substr($u, 0, rindex($u, '/'));
									$link = "http://" . $u . '/' . $link;
								}
							}
							else{
								$u =~s/https:\/\///g;
								if($link =~/^\.\.\//){
									while($link =~ /^\.\.\//){
										$link = substr($link, 3, length($link));
										$u = substr($u, 0, rindex($u, '/'));
										$u = substr($u, 0, rindex($u, '/')+1);
									}
									$link = "https://" . $u . $link;
								 }
								else{
									$u = substr($u, 0, rindex($u, '/'));
									$link = "https://" . $u . '/' . $link;
								}
							}
						}
					
					}
					chomp $link;
					$link =~s/&amp;/&/g;
					$link =~ s/\.\///g; 
					$link =~ s/ //g;
					if($link =~/^https?:\/\// && $link =~/^$url/ && $link !~/#|javascript:|mailto:/){
						my $fil = $func->get_file($link);
						my $ext = &get_extension($fil);
						if($conf{extensions} !~/$ext/){
							$files{$fil}++;
							if($files{$fil} <= $conf{'variation'}){
								push (@lst,$link);
							}
						}
					}
				}
			}
		}
		return @lst;
	}
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

	printf("\r| [*] Crawling: [%d - %d]\r", $p, $u);
}



##############################################
#  Function start
#  this function start the crawler
#  
#
#  Param: nothing
#  Return: @array
##############################################


sub start(){
my $self = shift;
$q = new Thread::Queue;
foreach (@url_list){
$q->enqueue($_);
}
$u = scalar(@url_list);
$url = $url_list[0];
$func->write("| Crawler Started:");
$p++;
threads->new(\&crawling, $q->dequeue);
my @threads = threads->list;


while($q->pending() || scalar(@threads)){
		@threads = threads->list;
                if ($q->pending > 0) {
                        if  (scalar(@threads) < $conf{'max_threads'}) {
				if($p <= $conf{'max_reqs'}){
					$p++;
					printf("\r| [*] Crawling: [%d - %d]\r", $p, $u);
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
@threads = threads->list;
        foreach my $running (@threads) {
              $running->join();
        }
$func->write("| [+] Crawling finished, ". scalar(@list) ." URL's found!");
return @list;
}


##############################################
#  Function AddUrl
#  this function add a url on crawler
# 
#
#  Param: $url
#  Return: nothing
##############################################

sub AddUrl(){
my ($self, $ur) = @_;
push(@url_list, $ur) if($ur =~/^https?/);
}


##############################################
#  Function CheckRobots
#  this function check file /robots.txt
# 
#
#  Param: $url
#  Return: @array
##############################################

sub CheckRobots(){
	my ($self, $url) = @_;
	my $h = Uniscan::Http->new();
	my @found = ();
	my $content = $h->GET($url."robots.txt");
	if($content =~/Allow:|Disallow:/){
	    
		my @file = split("\n", $content);
		foreach my $f (@file){
			my ($tag, $dir) = split(' ', $f);
			if($dir){  
			push(@found, $url.$dir) if($dir =~/^\//);
		        $func->write("| [+] ".$dir);
			}
		}
	}
return @found;
}


##############################################
#  Function ShowEmail
#  this function show all email found by crawler
# 
#
#  Param: nothing
#  Return: nothing
##############################################

sub ShowEmail(){
	my $self = shift;
	foreach my $mail (%email){
		$func->write("| [+] E-mail Found: ". $mail . " " . $email{$mail} . "x times") if($email{$mail});
	}
}


##############################################
#  Function GetForms
#  this function return the forms found by
#  crawler
#
#  Param: nothing
#  Return: @array
##############################################

sub GetForms(){
	my $self = shift;
	my @f = ();
	foreach my $key (keys %forms){
	push(@f, $key.'#'.$forms{$key});
	}
	return @f;
}


sub Clear(){
	my $self = shift;
	%files = ( );
	@list = ( );
	%forms = ( );
	%urls = ( );
	$q = 0;
	$p = 0;
	$u = 0;
	$url = "";
	@url_list = ( );
	%email = ();
}


1;
