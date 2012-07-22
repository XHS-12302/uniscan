package Plugins::Crawler::checkUploadForm;

use Uniscan::Functions;
use Thread::Semaphore;

my $func = Uniscan::Functions->new();
our %upload : shared = ();
my $semaphore = Thread::Semaphore->new();

sub new {
    my $class    = shift;
    my $self     = {name => "Upload Form Detect", version => 1.0 };
    our $enabled = 1;
    return bless $self, $class;
}

sub execute {
    my $self = shift;
	my $url = shift;
	my $content = shift;
	while($content =~ m/<input(.+?)>/gi){
		my $params = $1;
		if($params =~ /type *= *"file"/i){
			$semaphore->down();
			$upload{$url}++;
			$semaphore->up();
		}
	}
	

}


sub showResults(){
	my $self = shift;
	$func->write("|\n| File Upload Forms:");
	$func->writeHTMLItem("File Upload Forms:<br>");
	foreach my $url (%upload){
		$func->write("| [+] Upload Form Found: ". $url . " " . $upload{$url} . "x times") if($upload{$url});
		$func->writeHTMLValue("Upload Form Found: ". $url) if($upload{$url});
		
	}
}

sub getResults(){
	my $self = shift;
	return %upload;
}

sub clean(){
	my $self = shift;
	%upload = ();
}

sub status(){
	my $self = shift;
	return $enabled;
}

1;
