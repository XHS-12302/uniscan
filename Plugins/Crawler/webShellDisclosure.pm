package Plugins::Crawler::webShellDisclosure;

use Uniscan::Functions;

# this plug-in search for web backdoors while crawler is running.

my $func = Uniscan::Functions->new();

my @wb = (	"c99shell<\/title>",
		"C99Shell v",
		"<form method=\"POST\" action=\"cfexec\.cfm\">",
		"<input type=text name=\".CMD\" size=45 value=",
		"<title>awen asp\.net webshell<\/title>",
		"<FORM METHOD\=GET ACTION\='cmdjsp\.jsp'>",
		"JSP Backdoor Reverse Shell",
		"Simple CGI backdoor by DK",
		"execute command: <input type=\"text\" name=\"c\">",
		"Execute Shell Command",
		"r57shell<\/title>",
		"heroes1412",
		"MyShell",
		"PHP Shell",
		"PHPShell",
		"REMVIEW TOOLS",
);

sub new {
	my $class    = shift;
	my $self     = {name => "Web Backdoor Disclosure", version => 1.0};
	our %shells : shared = ();
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;

	foreach my $w (@wb){
		if($content =~m/$w/gi){
			$shells{$url}++;
		}
	}
}


sub showResults(){
	my $self = shift;
	$func->write("|\n| Web Backdoors:");
	foreach my $w (keys %shells){
		$func->write("| [+] Possible Backdoor: ". $w . " " . $shell{$w} . "x times") if($shells{$w});
	}
}

sub getResults(){
	my $self = shift;
	return %shells;
}

sub clean(){
	my $self = shift;
	%shells = ();
}


sub status(){
	my $self = shift;
	return $enabled;
}

1;

