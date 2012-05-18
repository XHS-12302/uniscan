#!/usr/bin/perl
use Tk;
use LWP::UserAgent;
use HTTP::Response;
#DIR WHERE uniscan ARE INSTALLED,EDIT BELLOW.
$dir= $0;
###############################################
# Main Window
my $mw = new MainWindow; 
$mw->geometry("600x500");
$mw->minsize(qw(550 125));
$mw->maxsize(qw(550 125)); 
$mw->title("uniscan Guix");

$| = 1;


#widgets positions#
my $frame = $mw -> Frame(-relief=>'raised',
  -borderwidth=>1,
  ) ->pack(-side=>'top', -fill=>'x');  
my $frametype = $mw -> Frame(-relief=>'raised',
  -borderwidth=>1,
  ) ->pack(-side=>'right',-anchor => 'nw');
my $framerelat = $frametype -> Frame(-relief=>'raised',
  -borderwidth=>1,
  ) ->pack(-side=>'top',-anchor => 'nw',-fill=>'x'); 
my $frameinfo = $mw -> Frame(-relief=>'raised',
  -borderwidth=>1,
  ) ->place(-x => 0, -y => 35); 
my $exitbot = $mw -> Frame(-relief=>'raised',
  -borderwidth=>1,
  ) ->place(-x => 300, -y => 35); 
my $framecc = $mw -> Frame(-relief=>'raised',
  -borderwidth=>1,
  ) ->place(-x => 146, -y => 488); 
#URL Settings#
my $labelurl = $frame -> Label(-text=>"URL:") -> pack(-side => 'left',
                                           -expand => 1);
my $urlentry = $frame -> Entry(-width => 50)  -> pack(-side => 'left',
                                              -expand => 1);
my $botaogo = $frame -> Button(-text => 'GO!', -command =>\&botaogo) -> pack(-side => 'left',
                                              -expand => 1);
my $url = $urlentry -> insert('end',"-u http://portalcplusplus.com.br/ -qwedsgj");	


#relatorio
my $botaorelat = $framerelat -> Button(-text => 'Relatorio', -command =>\&botaorelatorio) -> pack(-side => 'bottom',
                                              -expand => 1);

#exit bot##
my $botaoexit = $exitbot -> Button(-text => 'Exit', -command =>\&botaoexit) -> pack(-side => 'left',
                                         -expand => 1,-fill=>'x',-ipadx=>'55');
#Info #
my $info = $frameinfo -> Label(-text=>"- Uniscan Gui -\nBy Roberto Carlos Neves\nportalcplusplus.com.br\ncontato\@portalcplusplus.com.br",-width => 42,-height => 5) -> pack(-side=>'top',-fill=>'x');
MainLoop;
#Função#

sub botaorelatorio {

  system("kate uniscan.log");
 
}

sub botaogo {

$urlreal = $urlentry -> get();
chdir "$dir";
system("clear");
#print "perl uniscan.pl $urlreal";
system("perl uniscan.pl $urlreal" );
}
sub botaoexit {
exit;
}

