package Plugins::Tests::Dynamic::9_directoryAdd;

use Uniscan::Functions;
my $func = Uniscan::Functions->new();


# this plug-in compares the directory names in the file Directory with the name of directories found by the crawler
# if the name does not exist in the file, it will be included

sub new {
	my $class    = shift;
	my $self     = {name => "Learning New Directories", version=>1.2};
	our $enabled  = 1;
	return bless $self, $class;
	our %dir = ();
}


sub execute(){
	my ($self,@urls) = @_;
	open(a, "<Directory");
	my @line = <a>;
	close(a);
	my $x=0;

	foreach my $d (@urls){
		$d =~ s/https?:\/\///g;
		substr($d, 0, index($d, '/')) = "";
		my @directories = split('/', $d);
		pop(@directories);
		foreach my $d (@directories){
			$d =~ s/\///g;
			$d .= '/';
			$d =~s/\r//g;
			chomp($d);
			if(($d =~ /^\w+\/$/) && (length($d)>2) && (length($d)<15) && $d !~/^\d+\/$/){
				my $e = 0;
				foreach my $l (@line){
					chomp $l;
					$e = 1 if($d eq $l);
				}
				if($e == 0){
					$dirs{d} = 1;
					push(@line, $d);
					$x++;
				}
			}
		}
	}
	open(a, ">Directory");
	my @dir = sort(@line);
	foreach my $l (@dir){
		chomp $l;
		print a "$l\n";
	}
	close(a);
	$func->writeHTMLItem("Learning New Directories: ");
	$func->write("| [+] $x New directories added");
	$func->writeHTMLValue("$x New directories added.");
}

sub clean{
	my $self = shift;
}



sub status(){
	my $self = shift;
	return $enabled;
}




1;

