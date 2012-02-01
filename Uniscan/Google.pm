package Uniscan::Google;

use Moose;
use Uniscan::Functions;
use Uniscan::Http;

my $func = Uniscan::Functions->new();
my $http = Uniscan::Http->new();
our %inputs = ();

sub search(){
	my ($self, $search) = @_;

	my $n = 0;
	my $google = "";
	my %sites = ();
	$func->write("| [+] Google search for: $search");
	for($n=0; $n<200; $n+=10){
		$google = 'http://www.google.com.br/#q='. $search .'&hl=pt-BR&&start='. $n .'&fp=1';
		my $response = $http->GET($google);
		while ($response =~  m/<a href=\"https?:\/\/([^>\"]+)\" class=l>/g){
			if ($1 !~ m/google|cache|translate/){
				my $site = $1;
				$site = substr($site, 0, index($site, '/')) if($site =~/\//);
				if(!$sites{$site}){
					$sites{$site} = 1;
				}
			}
		}
	}

	my $i =0;
	open(my $file, ">>sites.txt");
	foreach my $key (keys %sites){
		print $file "http://" . $key . "/\n";
		$i++;
	}
	close($file);
	$func->write("| [+] Google returns $i sites.");
	$func->write("| [+] Google search finished.");

}

1; 