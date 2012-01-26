package Plugins::Crawler::phpinfo;

use Uniscan::Functions;

# this plug-in identify phpinfo() function on webpages

my $func = Uniscan::Functions->new();


sub new {
	my $class    = shift;
	my $self     = {name => "phpinfo() Disclosure", version => 1.0};
	our %pages : shared = ();
	our %info  : shared = ();
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;

	if($content =~m/<title>phpinfo\(\)<\/title>/gi){
		$pages{$url}++;

		while($content =~m/<tr><td class="e">(.+?) <\/td><td class="v">(.+?)<\/td><\/tr>/g){
			$info{$1} = $2;
		}

		while($content =~m/<tr><td class="e">(.+?)<\/td><td class="v">(.+?)<\/td><td class="v">(.+?)<\/td><\/tr>/g){
			$info{$1} = $2;
		}
	}
}


sub showResults(){
	my $self = shift;
	$func->write("|\n| phpinfo() Disclosure:");
	foreach my $w (keys %pages){
		$func->write("| [+] phpinfo() page: ". $w . " " . $pages{$w} . "x times") if($pages{$w});
	}
	$func->write("| \tSystem: ". $info{'System'}) if($info{'System'});
	$func->write("| \tPHP version: ". $info{'PHP Version'}) if($info{'PHP Version'});
	$func->write("| \tApache Version: ". $info{'Apache Version'}) if($info{'Apache Version'});
	$func->write("| \tServer Administrator: ". $info{'Server Administrator'}) if($info{'Server Administrator'});
	$func->write("| \tUser/Group: ". $info{'User/Group'}) if($info{'User/Group'});
	$func->write("| \tServer Root: ". $info{'Server Root'}) if($info{'Server Root'});
	$func->write("| \tDOCUMENT_ROOT: ". $info{'DOCUMENT_ROOT'}) if($info{'DOCUMENT_ROOT'});
	$func->write("| \tSCRIPT_FILENAME: ". $info{'SCRIPT_FILENAME'}) if($info{'SCRIPT_FILENAME'});
	$func->write("| \tallow_url_fopen: ". $info{'allow_url_fopen'}) if($info{'allow_url_fopen'});
	$func->write("| \tallow_url_include: ". $info{'allow_url_include'}) if($info{'allow_url_include'});
	$func->write("| \tdisable_functions: ". $info{'disable_functions'}) if($info{'disable_functions'});
	$func->write("| \tsafe_mode: ". $info{'safe_mode'}) if($info{'safe_mode'});
	$func->write("| \tsafe_mode_exec_dir: ". $info{'safe_mode_exec_dir'}) if($info{'safe_mode_exec_dir'});
	$func->write("| \tOpenSSL Library Version: ". $info{'OpenSSL Library Version'}) if($info{'OpenSSL Library Version'});
}

sub getResults(){
	my $self = shift;
	return %pages;
}

sub clean(){
	my $self = shift;
	%pages = ();
	%info = ();
}


sub status(){
	my $self = shift;
	return $enabled;
}

1;

