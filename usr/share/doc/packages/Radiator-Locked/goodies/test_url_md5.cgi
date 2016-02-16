#!/usr/bin/perl

use Digest::MD5  qw(md5_base64); 

print "Content-type: text/html\n\n";

use CGI;
my $cgi= new CGI;
my $user = $cgi->param('u');
my $p = $cgi->param('c');
my $correct_password = 'p';
my $md=md5_base64($user .$correct_password );

if ($user eq 'm' && $p eq $md){
print "all ok!!!!!";
} else {
print "all bad!!";
}

