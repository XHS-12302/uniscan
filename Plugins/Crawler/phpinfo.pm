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
	}

	if($content =~m/<tr><td class="e">PHP Version <\/td><td class="v">(.+?)<\/td><\/tr>/gi){
		$info{'PHP version'} = $1;  
	}
	if($content =~m/<tr><td class="e">System <\/td><td class="v">(.+?)<\/td><\/tr>/g){
		$info{'System'} = $1;
	}
	if($content =~m/<tr><td class="e">Apache Version <\/td><td class="v">(.+?)<\/td><\/tr>/g){
		$info{'Apache Version'} = $1;
	}
	if($content =~m/<tr><td class="e">Server Administrator <\/td><td class="v">(.+?)<\/td><\/tr>/g){
		$info{'Server Administrator'} = $1;
	}
	if($content =~m/<tr><td class="e">Server Root <\/td><td class="v">(.+?)<\/td><\/tr>/g){
		$info{'Server Root'} = $1;
	}
	if($content =~m/<tr><td class="e">SCRIPT_FILENAME <\/td><td class="v">(.+?)<\/td><\/tr>/g){
		$info{'Script Filename'} = $1;
	}
	if($content =~m/<tr><td class="e">SERVER_SIGNATURE <\/td><td class="v">(.+?)<\/td><\/tr>/g){
		$info{'Server Signature'} = $1;
	}
	if($content =~m/<tr><td class="e">allow_url_fopen<\/td><td class="v">(.+?)<\/td><td class="v">(.+)<\/td><\/tr>/g){
		$info{'allow_url_fopen'} = $1;  
	}
	if($content =~m/<tr><td class="e">allow_url_fopen<\/td><td class="v">(.+?)<\/td><td class="v">(.+)<\/td><\/tr>/g){
		$info{'allow_url_fopen'} = $1;  
	}
	if($content =~m/<tr><td class="e">allow_url_include<\/td><td class="v">(.+?)<\/td><td class="v">(.+)<\/td><\/tr>/g){
		$info{'allow_url_include'} = $1;  
	}
	if($content =~m/<tr><td class="e">register_globals<\/td><td class="v">(.+?)<\/td><td class="v">(.+)<\/td><\/tr>/g){
		$info{'register_globals'} = $1;  
	}
	if($content =~m/<tr><td class="e">safe_mode<\/td><td class="v">(.+?)<\/td><td class="v">(.+)<\/td><\/tr>/g){
		$info{'safe_mode'} = $1;  
	}
	if($content =~m/<tr><td class="e">safe_mode_exec_dir<\/td><td class="v">(.+?)<\/td><td class="v">(.+)<\/td><\/tr>/g){
		$info{'safe_mode_exec_dir'} = $1;  
	}

}


sub showResults(){
	my $self = shift;
	$func->write("|\n| phpinfo() Disclosure:");
	foreach my $w (keys %pages){
		$func->write("| [+] phpinfo() page: ". $w . " " . $pages{$w} . "x times") if($pages{$w});
	}
	foreach my $key (keys %info){
		print "| \t$key: ". $info{$key} . "\n";
	}
}

sub getResults(){
	my $self = shift;
	return %pages;
}

sub clean(){
	my $self = shift;
	%pages = ();
}


sub status(){
	my $self = shift;
	return $enabled;
}

1;

