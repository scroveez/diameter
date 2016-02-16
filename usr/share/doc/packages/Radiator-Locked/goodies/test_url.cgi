#!/usr/bin/perl

print "Content-type: text/html\n\n";
use CGI;
my $cgi= new CGI;
my $u=$cgi->param('u');
my $p=$cgi->param('c');

if ($u eq 'm' && $p eq 'p'){
print "all ok!!!!!";
} elsif($u eq 'm') {
    print "wrong pass!!!";
} elsif($p eq 'pepe') {
    print "wrong user!!!";
} else {
print "all bad!!";
}


