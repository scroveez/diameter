#! /usr/bin/perl
#
# checkrad.pl	See if a user is (still) logged in on a certain port.
#
#		This is used by the cistron-radius server to check
#		if it's idea of a user logged in on a certain port/nas
#		is correct if a double login is detected.
#
# Called as:	nas_type nas_ip nas_port login session_id
#
# Returns:	0 = no duplicate, 1 = duplicate, >1 = error.
#
# Version:	@(#)checkrad.pl  1.04  21-Sep-1997  miquels@cistron.nl
#

#
#	Config:	$debug is the file you want to put debug messages in
#		$snmpget is the location of your snmpget program
#		$lvm is the Livingston SNMP MIB
#
#$debug   = '';
$debug   = '/tmp/checkrad.debug';
$snmpget = '/usr/bin/snmpget';
$lvm     = '.iso.org.dod.internet.private.enterprises.307';
$pmwho   = '/usr/local/sbin/pmwho';
#
#	PM3:	$lv_offs is where the last S port is before one or two
#		ports are skipped (22 or 29, for US or Europe)
#		$lv_hole is the size of the hole (1 or 2, for US or Europe).
$lv_offs = 29;
$lv_hole = 2;

#
#	See if the user is logged in using the Livingston MIB.
#	We don't check the username but the session ID.
#
sub livingston_snmp {

	#
	#	First find out the offset (ugly!!). Also, if the portno
	#	is greater than 29, substract 2 (S30 and S31 don't exist).
	#	You might need to change this to 23 and 1 for the USA.
	#
	$_ = `$snmpget $ARGV[1] mitec $lvm.3.2.1.1.1.2.5`;
	($xport) = /^.*\"S([0-9]+)".*$/;
	$xport += 0;
	$portidx = $ARGV[2] + (5 - $xport);
	$portidx -= $lv_hole if ($ARGV[2] > $lv_offs);
	chop;
	print LOG "  using $xport offset for port / SNMPno translation\n"
		if ($debug);

	#
	#	Now get the session id from the terminal server.
	#
	$_ = `$snmpget $ARGV[1] mitec $lvm.3.2.1.1.1.5.$portidx`;
	($sessid) = /^.*\"([^"]+)".*$/;

	print LOG "  session id at port S$ARGV[2]: $sessid\n" if ($debug);

	($sessid eq $ARGV[4]) ? 1 : 0;
}

#
#	See if the user is logged in using the Cisco MIB
#
sub cisco_snmp {
	#
	#	Not implemented yet - should be easy based on livingston_snmp
	#
	0;
}

#
#	See if the user is logged in using the portslave finger.
#
sub portslave_finger {
	my ($Port_seen);

	$Port_seen = 0;

	open(FD, "finger \@$ARGV[1]|");
	while(<FD>) {
		#
		#	Check for ^Port. If we don't see it we
		#	wont get confused by non-portslave-finger
		#	output too.
		#
		if (/^Port/) {
			$Port_seen++;
			next;
		}
		next if (!$Port_seen);
		next if (/^---/);

		($port, $user) = /^.(...) (...............)/;

		$port =~ s/ .*//;
		$user =~ s/ .*//;
		$ulen = length($user);
		#
		#	HACK: strip [PSC] from the front of the username,
		#	and things like .ppp from the end.
		#
		$user =~ s/^[PSC]//;
		$user =~ s/\.(ppp|slip|cslip)$//;

		#
		#	HACK: because ut_user usually has max. 8 characters
		#	we only compare up the the length of $user if the
		#	unstripped name had 8 chars.
		#
		$argv_user = $ARGV[3];
		if ($ulen == 8) {
			$ulen = length($user);
			$argv_user = substr($ARGV[3], 0, $ulen);
		}

		if ($port == $ARGV[2]) {
			if ($user eq $argv_user) {
				print LOG "  $user matches $argv_user " .
					"on port $port" if ($debug);
				close FD;
				return 1;
			} else {
				print LOG "  $user doesn't match $argv_user " .
					"on port $port" if ($debug);
				close FD;
				return 0;
			}
		}
	}
	close FD;
	0;
}

sub totalcontrol_telnet {
# Added to determine whether a user is logged on to the
# Total Control using pmwho.

open (PMWHO, "$pmwho $ARGV[1]|");
	while (<PMWHO>)
	{
		next if (/Port/);
		next if (/---/);
		($port, $user) = split;
		$port =~ s/^S//;
		$user =~ s/^[PSC]//;
		$user =~ s/\.(ppp|slip|cslip)$//;

		if ($port == $ARGV[2]) 
		{ 
			if ($user eq $ARGV[3]) {
				print LOG "   $user matches $ARGV[3] " .
					"on port $port" if ($debug);
				close (PMWHO);
				return 1;
			} else {
				print LOG "  $user doesn't match $ARGV[3] " .
					"on port $port" if (debug);
				close (PMWHO);
				return 0;
			}
		}
	}
	close (PMWHO);
	0;
}

if ($debug) {
	open(LOG, ">>$debug");
	$now = localtime;
	print LOG "$now checkrad @ARGV\n";
}

if ($#ARGV != 4) {
	print LOG "Usage: checkrad nas_type nas_ip " .
			"nas_port login session_id\n" if ($debug);
	print STDERR "Usage: checkrad nas_type nas_ip " .
			"nas_port login session_id\n";
	close LOG if ($debug);
	exit(2);
}

if ($ARGV[0] eq 'livingston') {
	$ret = &livingston_snmp;
} elsif ($ARGV[0] eq 'cisco') {
	$ret = &cisco_snmp;
} elsif ($ARGV[0] eq 'portslave') {
	$ret = &portslave_finger;
} elsif ($ARGV[0] eq 'totalcontrol') {
        $ret = &totalcontrol_telnet;
} elsif ($ARGV[0] eq 'other') {
	$ret = 0;
} else {
	print LOG "  checkrad: unknown NAS type $ARGV[0]\n" if ($debug);
	print STDERR "checkrad: unknown NAS type $ARGV[0]\n";
	$ret = 2;
}

if ($debug) {
	$mn = "login ok";
	$mn = "double detected" if ($ret == 1);
	$mn = "error detected" if ($ret == 2);
	print LOG "  Returning $ret ($mn)\n";
	close LOG;
}

exit($ret);
