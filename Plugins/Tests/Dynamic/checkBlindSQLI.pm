package Plugins::Tests::Dynamic::checkBlindSQLI;

use Uniscan::Configure;
use Uniscan::Functions;
use Thread::Queue;
use Uniscan::Http;
use threads;

	my $c = Uniscan::Configure->new(conffile => "uniscan.conf");
	my $func = Uniscan::Functions->new();
	my $http = Uniscan::Http->new();
	my $q = new Thread::Queue;

sub new {
	my $class    = shift;
	my $self     = {name => "Blind SQL-injection tests", version => 1.2};
	our $enabled  = 1;
	our %conf = ( );
	%conf = $c->loadconf();
	return bless $self, $class;
}


sub execute(){
	my ($self,@urls) = @_;

	$func->write("|"." "x99);
	$func->write("|"." "x99);
	$func->write("| Blind SQL Injection:");
	$func->writeHTMLItem("Blind SQL Injection:<br>");
	@urls = $func->remove(@urls) if(scalar(@urls));
	&threadnize("CheckNoError", @urls) if(scalar(@urls));
}

sub clean{
	my $self = shift;
}


sub CheckNoError(){
	while($q->pending > 0){
		my $url = $q->dequeue;
		next if(not defined $url);
		next if($url =~/\/\?S=A|\/\?N=D|\/\?S=D|\/\?D=A|\/\?N=A|\/\?M=D|\/\?M=A|\/\?D=D|\/\?D=A/g);
		if($url !~/#/){
			print "[*] Remaining tests: ". $q->pending ."        \r";
			if($url =~/\?/){
				my ($url1, $vars) = split('\?', $url);
				my @var = split('&', $vars);
				foreach my $v (@var){
					TestNoError($url, $v);
				}
			}
		}
	}
	$q->enqueue(undef);
}


sub TestNoError(){
	my ($url, $var) = @_;
	$url =~s/&$var//g;
	$url =~s/$var//g;
	$url .= "&" . $var;
	$url =~s/\?&/\?/g;
	my $url1 = $url;
	my $url2 = $url;
	my $url3 = $url;
	my $url4 = $url;
	$url1 =~ s/$var/$var\+AND\+1=1/g;
	$url2 =~ s/$var/$var\+AND\+1=2/g;
	my $r1 = $http->GET($url);
	my $r2 = $http->GET($url);
	next if(!$r1 or !$r2);
	my $r4 = $http->GET($url2);
	my $r5 = $http->GET($url1);
	next if(!$r4 or !$r5);
	$r1 =~ s/<script.+?<\/script>//gi;
	$r2 =~ s/<script.+?<\/script>//gi;
	$r1 =~s/<!DOCTYPE HTML PUBLIC ".+?">//gi;
	$r2 =~s/<!DOCTYPE HTML PUBLIC ".+?">//gi;
	
	my @w1 = split(' ', $r1);
	my $keyword = "";
	my $key = 0;
	foreach my $word (@w1){
		if($r2 =~ /\Q$word\E/g && $r4 !~ /\Q$word\E/g && length($word) > 5 && $word =~ /^\w+$/g){
			if($key == 0){
				$key =1;
				$keyword = $word;
			}
		}
	}
	if($r5 =~/\Q$keyword\E/g && $key == 1 && $r5 !~/<b>Warning<\/b>/gi && $r4 !~/\Q$keyword\E/g){
		$func->write("| [+] Vul [Blind SQL-i]: $url1     ");
		$func->write("| [+] Keyword: $keyword");
		$func->writeHTMLValue($url1);
		$func->writeHTMLValue("Keyword: $keyword");
	}



	################

	$url3 =~s/$var/$var'\+AND\+'1'='1/g;
	$url4 =~s/$var/$var'\+AND\+'1'='2/g;
	my $r6 = $http->GET($url3);
	my $r7 = $http->GET($url4);
	next if(!$r6 or !$r7);
	$key = 0;
	foreach my $word (@w1){
		if($r2 =~ m/\Q$word\E/g && $r7 !~m/\Q$word\E/g && length($word) > 5 && $word =~ m/^\w+$/g){
			if($key == 0){
				$key =1;
				$keyword = $word;
			}
		}
	}
	if($r6 =~/\Q$keyword\E/g && $key == 1 && $r6 !~/<b>Warning<\/b>/gi && $r7 !~/\Q$keyword\E/){
		$func->write("| [+] Vul [Blind SQL-i]: $url3     ");
		$func->write("| [+] Keyword: $keyword");
		$func->writeHTMLValue($url3);
		$func->writeHTMLValue("Keyword: $keyword");
	}
	($r1, $r2, $r4, $r5, @w1, $r6, $r7, $keyword) = undef;
}


sub status(){
 my $self = shift;
 return $enabled;
}

 sub threadnize(){
	my ($fun, @tests) = @_;
	foreach my $test (@tests){
		$q->enqueue($test) if($test && $test =~/=/);
	}

	my $x=0;
	my @threads = ();
	while($q->pending() && $x <= $conf{'max_threads'}-1){
		no strict 'refs';
		push @threads, threads->new(\&{$fun});
		$x++;
	}

	sleep(2);

	foreach my $running (@threads) {
		$running->join();
		print "[*] Remaining tests: ". $q->pending ."        \r";
	}
	@threads = ();
}


sub urlencode {
    my $s = shift;
    $s =~ s/ /+/g;
    $s =~ s/([^A-Za-z0-9\+-])/sprintf("%%%02X", ord($1))/seg;
    $s =~s/%7C/\|/g;
    $s =~ s/%25/%/g;
    return $s;
}



1;
