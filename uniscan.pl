#!/usr/bin/env perl

use lib "./Uniscan";
use Uniscan::Crawler;
use Uniscan::Functions;
use Uniscan::Scan;
use Uniscan::Bing;
use Uniscan::Google;
use Uniscan::FingerPrint;
use Uniscan::FingerPrint_Server;
use Uniscan::Configure;
use Getopt::Std;

my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
my %conf = $cfg->loadconf();
my $func = Uniscan::Functions->new();
my @urllist = ( );
my $scan;

$|++;

getopts('u:f:i:o:hbqwsdergj', \%args);
$func->createHTML();
$func->banner();
$func->CheckUpdate();

if($args{h}){
	$func->help();
}

if(!$args{u} && !$args{f} && !$args{i} && !$args{o}){
	$func->help();
}

if($args{u}){
	$func->check_url($args{u});
	push(@urllist, $args{u});
} 
elsif($args{f}){
	open(url_list, "<$args{f}") or die "$!\n";
	while(<url_list>){
		my $line = $_;
		chomp $line;
		$func->check_url($line);
		push(@urllist, $line);
	}
	close(url_list);
}
elsif($args{i} && $args{o}){
	$func->writeHTMLCategory("SEARCH ENGINE");
	$func->write("="x99);
  	$func->write("| Bing:");
	$func->writeHTMLItem("Bing:<br>");
  	my $bing = Uniscan::Bing->new();
  	$bing->search($args{i});
  	$func->write("| Site list saved in file sites.txt");
	$func->writeHTMLValue("Site list saved in file sites.txt");
  	$func->write("="x99);
	$func->writeHTMLItem("Google:<br>");
  	$func->write("| Google:");
  	my $google = Uniscan::Google->new();
  	$google->search($args{o});
	$func->writeHTMLValue("Site list saved in file sites.txt");
  	$func->write("| Site list saved in file sites.txt");
  	$func->write("="x99);
	$func->writeHTMLCategoryEnd();
}
elsif($args{i}){
	$func->writeHTMLCategory("SEARCH ENGINE");
 	$func->write("="x99);
  	$func->write("| Bing:");
	$func->writeHTMLItem("Bing Search:<br>");
  	my $bing = Uniscan::Bing->new();
  	$bing->search($args{i});
	$func->writeHTMLValue("Site list saved in file sites.txt");
  	$func->write("| Site list saved in file sites.txt");
	$func->writeHTMLCategoryEnd();
}
elsif($args{o}){
	$func->writeHTMLCategory("SEARCH ENGINE");
  	$func->write("="x99);
	$func->writeHTMLItem("Google Search:<br>");
  	$func->write("| Google:");
  	my $google = Uniscan::Google->new();
  	$google->search($args{o});
	$func->writeHTMLValue("Site list saved in file sites.txt");
  	$func->write("| Site list saved in file sites.txt");
  	$func->write("="x99);
	$func->writeHTMLCategoryEnd();
}
else{
    $func->help();
}

if($args{b}){
	&background();
	printf("Going to background with pid: [%d]\n", $$);
}




$func->DoLogin();


foreach my $url (@urllist){
	$func->createHTML();
	$func->write("Scan date: " . $func->date(0));

# check redirect and fix it
	my $crawler = Uniscan::Crawler->new();
	$func->writeHTMLCategory("TARGET");
	if($conf{'redirect'} == 1){
		$url = $func->CheckRedirect($url);
		my $url_temp = $url;
		my $proto = "";
		if($url_temp =~ /http:\/\//){
			$proto = "http://";
		}
		else{ $proto = "https://"; }
		$url_temp =~s/https?:\/\///g;
		if(rindex($url_temp, '/') != index($url_temp, '/')){
			$url_temp = $proto . substr($url_temp, 0, index($url_temp, '/')+1);
			$crawler->AddUrl($url_temp);
		}
	}


	$crawler->AddUrl($url);
	$func->write("="x99);
	$func->write("| Domain: $url");
	$func->writeHTMLItem("Domain:");
	$func->writeHTMLValue($url);
	my $time1 = time();
	$func->GetServerInfo($url);
	my $time2 = time();
	my $total_time = $time2 - $time1;
	$func->write("| Wait Time ".$total_time." seconds");
	
	if($total_time < 30){
		$func->write("| IP: ". $func->GetServerIp($url));
		$func->writeHTMLItem("Target IP:");
		$func->writeHTMLValue($func->GetServerIp($url));
		$func->writeHTMLCategoryEnd();
		$func->INotPage($url);
		$func->write("="x99);
		# web fingerprint
		if($args{g}){
			my $webf = Uniscan::FingerPrint->new();
			$func->writeHTMLCategory("WEB SERVER INFORMATION");
			$webf->fingerprint($url);
			$webf->bannergrabing($url);
			$func->writeHTMLCategoryEnd();
		}

		# server fingerprint
		if($args{j}){
			my $serverf = Uniscan::FingerPrint_Server->new();
			$func->writeHTMLCategory("SERVER INFORMATION");
			$serverf->fingerprintServer($url);
			$func->writeHTMLCategoryEnd();
		}

		# start checks to feed the crawler
		#DIRECTORY CHECKS
		$func->writeHTMLCategory("CRAWLING");
		if($args{q}) {
			$func->write("|\n| Directory check:");
			$func->writeHTMLItem("Directory check:<br>");
			my @dir = $func->Check($url, "Directory");
			foreach my $d (@dir){
				$crawler->AddUrl($d);
			}
			@dir   = ();
			$func->write("="x99);
		}
		#FILE CHECKS
		if($args{w}) {
			$func->write("|" . " "x99);
			$func->write("| File check:");
			$func->writeHTMLItem("File check:<br>");
			my @files = $func->Check($url, "Files");
			foreach my $f (@files){
				$crawler->AddUrl($f);
			}
			@files = ();
			$func->write("="x99);
		}
		#robots check
		if($args{e}){
			$func->write("|\n| Check robots.txt:");
			$func->writeHTMLItem("Check robots.txt:<br>");
			foreach my $f ($crawler->CheckRobots($url)){
				$crawler->AddUrl($f);
			}
			$func->write("="x99);
		}
		# end of checks to feed the crawler

		if($args{d}){
			# crawler start
			$func->write("|\n| Crawler Started:");
			$crawler->loadPlugins();
			our @urls = $crawler->start();
			our @forms = $crawler->GetForms();
			foreach (@forms){
				push(@urls, $_);
			}
			# crawler end
			$crawler->Clear();
			$crawler = 0;
		}
		$func->writeHTMLCategoryEnd();
		$scan = Uniscan::Scan->new() if(!$scan);
		if($args{d}){
			$func->writeHTMLCategory("DYNAMIC TESTS");
			#start dinamic and static tests
			$func->write("="x99);
			$func->write("| Dynamic tests:");
			$scan->loadPluginsDynamic();
			$scan->runDynamic(@urls);
			$func->writeHTMLCategoryEnd();
		}
	
		if($args{s}){
			$func->writeHTMLCategory("STATIC TESTS");
			$func->write("="x99);
			$func->write("| Static tests:");
			$scan->loadPluginsStatic();
			$scan->runStatic($url);
			$func->writeHTMLCategoryEnd();
		}
	
		if($args{r}){
			use Uniscan::Stress;
			my $stress = Uniscan::Stress->new();
			$func->write("="x99);
			$func->writeHTMLCategory("STRESS TESTS");
			$func->write("| Stress tests:");
			$stress->loadPlugins();
			$stress->run($url);
			$func->writeHTMLCategoryEnd();
		}
		$func->write("="x99);
		$func->write("Scan end date: " . $func->date(1) . "\n\n\n");
	}
	else{
		$func->write("| [-] Request Timeout");
	}
	$func->writeHTMLEnd();
	$func->MoveReport($url);
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
	our $pid = fork;
	exit if $pid;
	die "Fork problem: $!\n" unless defined($pid);
}
