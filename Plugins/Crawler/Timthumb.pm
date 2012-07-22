package Plugins::Crawler::Timthumb;

use Uniscan::Functions;

	my $func = Uniscan::Functions->new();
	my %tim = ();

sub new {
    my $class    = shift;
    my $self     = {name => "Timthumb <= 1.32 vulnerability", version => 1.0};
    our $enabled = 1;
    return bless $self, $class;
}

sub execute {
    my $self = shift;
	my $url = shift;
	my $content = shift;

	if($content =~m/TimThumb version : (.+)<\/pre>/g){
		$tim{$url} = $1 if($1 < 1.33);
	}
}


sub showResults(){
	my $self = shift;
	$func->write("|\n| Timthumb:");
	$func->writeHTMLItem("Timthumb:<br>");
	foreach my $url (keys %tim){
		$func->write("| [+] Timthumb: ". $url . " V" . $tim{$url}) if($tim{$url});
		$func->writeHTMLValue("Timthumb: ". $url) if($tim{$url});
	}
}

sub getResults(){
	my $self = shift;
	return %tim;
}

sub clean(){
	my $self = shift;
	%tim = ();
}


sub status(){
	my $self = shift;
	return $enabled;
}

1;
