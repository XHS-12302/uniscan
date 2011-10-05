package Plugins::Tests::Static::checkPUT;

use Uniscan::Http;
use Uniscan::Functions;

sub new {
    my $class    = shift;
    my $self     = {name => "PUT method test", version => 1.0};
	our $enabled  = 1;
	our $func = Uniscan::Functions->new();
	our $http = Uniscan::Http->new();
    return bless $self, $class;
}


sub execute(){
	my ($self,$url) = @_;

	$func->write("|"." "x99);
	$func->write("|"." "x99);
	$func->write("| Test PUT mothod:");
    &CheckPut($url);
	}

	
sub CheckPut(){
	my $url = shift;
	my $h = Uniscan::Http->new();
	my $resp = $h->PUT($url."uniscan.txt", "uniscan123 uniscan123");
	$resp = $h->GET($url."uniscan.txt");
	if($resp =~/uniscan123/){
		$vulnerable++;
		$func->write("="x100);
		$func->write("| PUT method is enabled");
		$func->write("| [+] Vul[$vulnerable]: $url/uniscan.txt");
		$func->write("="x100);
	}
}

sub status(){
 my $self = shift;
 return $enabled;
}



1;
