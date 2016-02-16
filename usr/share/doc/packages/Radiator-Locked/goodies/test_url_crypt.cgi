#!/usr/bin/perl

print "Content-type: text/html\n\n";
use CGI;
my $cgi= new CGI;
my $u=$cgi->param('u');
my $p=$cgi->param('c');

my $cr=crypt('p','m');

if ($u eq 'm' && $p eq $cr){
print "all ok!!!!!";
} else {
print "all bad!!";
}

