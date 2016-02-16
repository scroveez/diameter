#!/usr/bin/perl
#
# 2011-03-24 rpt.pl - radiator packet tracer - Bart Dumon - bartdu(at)bsp(dot)scarlet(dot)be
# match anything in request packet(s), shows corresponding response packet(s)
# requires a <monitor> clause, cfr section 5.91 of the Radiator manual

# change the line below to match your configuration 
my ($monhost, $monport, $monuser, $monpass) = qw/localhost 9048 myuser mypass/;

use strict;
use Net::Telnet;
use Getopt::Std;

my %o;
getopts('t:e:qh',\%o);
my $type = ""; 
my $regexp = $o{'e'};

if ($o{'h'}) {
  print "usage: $0 [-h] [-q] [-t acct|auth] [-e <regexp>]\n";
  print "\t-h\tthis help\n";
  print "\t-q\tdo not show packet contents\n";
  print "\t-t\tpacket type: auth, acct or anything\n";
  print "\t-e\tregular expression matching request packet(s)\n";
  print "examples:\n";
  print "\t$0 -t auth -e \"User-Name = joe\"\n";
  print "\t$0 -q\n";
  print "\t$0 -t acct -e \"Framed-IP-Address = 10\\.23\\.1[789]\\..*User-Name = .*\@REALM\"\n";
  exit;
}

$type = $o{'t'} if ($o{'t'}); $type = "" if ($type ne "auth" && $type ne "acct");
$regexp = ".*" if (!$regexp);

my ($pkts, $drop) = qw/0 0/; # counters
my ($pkt, $pf, $id, $nas);
my (%idau, %idac); # saved id's of auth/acct packets

$SIG{INT} = \&interrupt; # catch ctrl-c

my $t = new Net::Telnet(Timeout => 3);
$t->open(Host => $monhost, Port => $monport);
$t->print("login ".$monuser." ".$monpass); print $t->getline;
$t->print("trace 4"); print $t->getline;

print "tracing packets matching \"$regexp\"\npress ctrl-c to exit...\n";
while (my $l = $t->getline) {
  $l =~ s/"//g; # ignore double quotes, 
  if ($l =~ m/^Identifier:\s+(\d+)$/) { $id = $1; }
  if ($l =~ m/^LOG.*Packet dump:$/) { $pf = 1; }
  if ($l =~ m/^\*\*\*\s+\w+\s+\w+\s+(\S+)/) { $nas = $1; }
  if ($l =~ m/^$/) { 
    # sort attributes alphabetically
    my ($npkt, @attr);
    for my $n (split("\n", $pkt)) {
      push(@attr, $n) && next if ($n =~ m/^\t\S+\s=\s.*$/);
      $npkt .= $n."\n";
    }
    $pkt = $npkt . join("\n", sort @attr);
    undef($npkt);
 
    # find response packets
    for my $id (keys %{$idau{$nas}}) {
      if ($pkt =~ m/\nCode:\s+Access.*\nIdentifier:\s+$id\n/) { prntpkt($pkt); delete($idau{$nas}{$id}); $pkt = ""; }
      delete($idau{$nas}{$id}) && $drop++ if (defined $idau{$nas}{$id} && $idau{$nas}{$id} < time()-30); # expire id's after 30 sec
    }
    for my $id (keys %{$idac{$nas}}) {
      if ($pkt =~ m/\nCode:\s+Accounting.*\nIdentifier:\s+$id\n/) { prntpkt($pkt); delete($idac{$nas}{$id}); $pkt = ""; }
      delete($idac{$nas}{$id}) && $drop++ if (defined $idac{$nas}{$id} && $idac{$nas}{$id} < time()-30); # expire id's after 30 sec
    }

    # print matching request packets
    if ($pkt =~ m/$regexp/s) {
      if ($pkt =~ m/\nCode:\s+Accounting/ && ($type eq "acct" || !$type)) {
        prntpkt($pkt); $idac{$nas}{$id} = time();
      }
      if ($pkt =~ m/\nCode:\s+Access/ && ($type eq "auth" || !$type)) {
        prntpkt($pkt); $idau{$nas}{$id} = time();
      }
    }
    $pf = 0; $pkt = ""; $nas = "";
  }
  next if ($l =~ m/^Authentic:/);
  $pkt .= $l if ($pf);
}

sub prntpkt {
  my $pkt = $_[0];
  $pkts++;
  if ($o{'q'}) {
    if ($pkt =~ m/LOG\s+\S+\s+\S+\s+(.*)\s+\d+\s+\d+:\s+DEBUG.*\n\*\*\*\s+(\S+)\s+\S+\s+(\S+)\s+\S+\s+(\d+).*\nCode:\s+(\S+)\nIdentifier:\s+(\d+)\n/) {
      my $dir = ($2 eq "Received") ? "<-" : "->";
      print "[".$1."] (".sprintf("%03d", $6).") - ".$5." ".$dir." ".$3.":".$4."\n";
    } 
    return;
  }
  print $pkt;
  return;
}

sub interrupt {
  $SIG{INT} = \&interrupt;
  print "\ninterrupted\n";
  $t->print("trace 2") if ($t);
  $t->print("quit") if ($t);
  $t->close() if ($t);
  print "packets: ".$pkts."\n";
  print "dropped: ".$drop."\n";
  exit 0;
}
