#!/usr/bin/env perl

use lib "./Uniscan";
use Uniscan::Crawler;
use Uniscan::Functions;
use Uniscan::Scan;
use Getopt::Std;

my $func = Uniscan::Functions->new();
my @urllist = ( );



getopts('u:f:hbqwertyiopasdgj', \%args);

$func->banner();
$func->CheckUpdate();
if($args{h}){
	$func->help();
}

if(!$args{u} && !$args{f}){
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
else{
    $func->help();
}

if($args{b}){
	&background();
	printf("Going to background with pid: [%d]\n", $$);
}


$|++;

$func->DoLogin();

foreach my $url (@urllist){

	$func->write("Scan date: " . $func->date());
	system("rm -rf temp.txt");

	my $crawler = Uniscan::Crawler->new();
	$crawler->Clear();
	$crawler->AddUrl($url);

	$func->write("="x99);
	$func->write("| Domain: $url");
	$func->GetServerInfo($url);
	$func->write("| IP: ". $func->GetServerIp($url));
	$func->INotPage($url);

	$func->write("="x99);
	if(!$args{q}) {
		$func->write("| Directory check:");
		my @dir = $func->Check($url, "Directory");
		foreach my $d (@dir){
			$crawler->AddUrl($d);
		}
		@dir   = ();
	}

	if(!$args{w}) {
		$func->write("| File check:");
		my @files = $func->Check($url, "Files");
		foreach my $f (@files){
			$crawler->AddUrl($f);
		}
		@files = ();
	}

	if(!$args{d}){
		$func->write("| Check robots.txt:");
		foreach my $f ($crawler->CheckRobots($url)){
			$crawler->AddUrl($f);
		}
	}





	my @urls = $crawler->start();
	if(!$args{j}){
		$func->write("| ");
		$crawler->ShowEmail();
	}
	my @forms = $crawler->GetForms();
	$crawler->Clear();
	$crawler = 0;
	my $scan = Uniscan::Scan->new();
	$scan->Clear();
	if(!$args{g}){
		$func->write("| Check if PUT method is enabled:");
		$scan->CheckPut($url);
	}

	if(!$args{e}){
		$scan->CheckBackupFiles(@urls) if(scalar(@urls));
	}

	if(!$args{r}){
		$func->write("| RFI tests:" . " "x88);
		$scan->ScanRFICrawler(@urls) if(scalar(@urls));
		$scan->ScanRFICrawlerPost(@forms) if(scalar(@forms));
	}

	if(!$args{t}){
		$func->write("| LFI tests:" . " "x88);
		$scan->ScanLFICrawler(@urls) if(scalar(@urls));
		$scan->ScanLFICrawlerPost(@forms) if(scalar(@forms));
	}

	if(!$args{y}){
		$func->write("| RCE tests:" . " "x88);
		$scan->ScanRCECrawler(@urls) if(scalar(@urls));
		$scan->ScanRCECrawlerPost(@forms) if(scalar(@forms));
	}

	if(!$args{o}){
		$func->write("| XSS tests:" . " "x88);
		$scan->ScanXSSCrawler(@urls) if(scalar(@urls));
		$scan->ScanXSSCrawlerPost(@forms) if(scalar(@forms));
	}

	if(!$args{i}){
		$func->write("| SQL-i tests:" . " "x78);
		$scan->ScanSQLCrawler(@urls) if(scalar(@urls));
		$scan->ScanSQLCrawlerPost(@forms) if(scalar(@forms));
	}


	$func->write("| Static Checks: ". " "x83) if(!$args{p} || !$args{a} || !$args{s});

	if(!$args{p}){
		$func->write("| RFI: " . " "x92);
		$scan->ScanStaticRFI($url);
	}

	if(!$args{a}){
		$func->write("| LFI: " . " "x92);
		$scan->ScanStaticLFI($url);
	}

	if(!$args{s}){
		$func->write("| RCE: " . " "x92);
		$scan->ScanStaticRCE($url);
	}
	$func->write("="x99);
	$func->write("Scan end date: " . $func->date() . "\n\n\n");
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
