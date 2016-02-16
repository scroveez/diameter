#!/usr/bin/perl
#
# testcommand
# Example to demonstrate how to handle AuthBy EXTERNAL, using
# a perl script
#
# The incoming attributes are on stdin, one per line in to format
# <tab>attribute-name = value
# Some will have quoted values, and some wont
# 
while (<>)
{
    chomp;

    if ($_ =~ /^\s*([^\s=]+)\s*=\s*"((\\"|[^"])*)"/)
    {
	# Quoted value
	$input{$1} = $2;
    }
    elsif ($_ =~ /^([^\s=]+)\s*=\s*(.*)/)
    {
	# Unquoted value
	$input{$1} = $2;
    }
}

# Now have all the incoming attributes in %input
# As a test we will see if User-Name is fred. If so,
# we will accept, else reject with a suitable Reply-Message
# You can set other reply attributes too, if you like.
# The exit value indicates accept or reject:
# 0 = Accept
# 1 = Reject
# 2 = Ignore
# 3 = Challenge
# Alternatively you can print one of the strings ACCEPT, REJECT
# IGNORE CHALLENGE or REJECT_IMMEDIATE on the first line if
# you are using ResultInOutput
if ($input{'User-Name'} eq 'fred')
{
#    print "ACCEPT\n"; # If you are using ResultInOutput
    print "Framed-IP-Address=1.2.3.4\n";
    print "Reply-Message=\"you are fred\"";
    sleep 1;
    exit 0; # accept, if not using ResultInOutput
}
else
{
#    print "REJECT\n"; # If you are using ResultInOutput
    print "Reply-Message=\"you are NOT fred, you are '$input{'User-Name'}'\"";
    sleep 1;
    exit 1; # reject, if not using ResultInOutput
}

