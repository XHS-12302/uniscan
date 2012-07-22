package Plugins::Crawler::externalHost;

use Uniscan::Functions;
use URI;

	my $func = Uniscan::Functions->new();
	my %external = ();

sub new {
    my $class    = shift;
    my $self     = {name => "External Host Detect", version => 1.2};
	our $enabled = 1;
    return bless $self, $class;
}

sub execute {
    my $self = shift;
	my $url = shift;
	my $content = shift;
    my $url_uri = &host($url);
	$url = $func->get_url($url);
	my @ERs = (	"href=\"(.+)\"", 
				"href='(.+)'", 
				"href=(.+?)>", 
				"location.href='(.+)'",
				"src='(.+)'",
				"src=\"(.+)\"",
				"location.href=\"(.+)\"", 
				"<meta.*content=\"?.*;URL=(.+)\"?.*?>"
			);
			
	foreach my $er (@ERs){
		while ($content =~  m/$er/gi){
			my $link = $1;
			next if($link =~/[\s"']/);
			$link = &get_url($link);
			if($url ne $link){
                if($link !~ /$url_uri/){
					$external{$link}++ if($link);
 			    }
			}
		}
	}
	

}


sub showResults(){
	my $self = shift;
	$func->write("|\n| External hosts:");
	$func->writeHTMLItem("External hosts:<br>");
	foreach my $url (%external){
		$func->write("| [+] External Host Found: ". $url . " " . $external{$url} . "x times") if($external{$url});
		$func->writeHTMLValue("External Host Found: ". $url) if($external{$url});
	}
}

sub getResults(){
	my $self = shift;
	return %external;
}

sub clean(){
	my $self = shift;
	%external = ();
}

sub status(){
	my $self = shift;
	return $enabled;
}

sub get_url(){
	my $url = shift;
	if($url =~/http:\/\//){
		$url =~s/http:\/\///g;
		$url = substr($url, 0, index($url, '/')) if($url =~/\//);
		return "http://" . $url;
	}
	if($url =~/https:\/\//){
		$url =~s/https:\/\///g;
		$url =  substr($url, 0, index($url, '/')) if($url =~/\//);
		return "https://" . $url;
	}
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



1;
