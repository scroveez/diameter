# Util.pm
#
# Utility routines required by Radiator
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) Open System Consultants
#
# strftime and supporting functions are based on code by David Muir Sharnoff 
# <muir@idiom.com> from  Time::CTime. That portion is covered by:
# Copyright (C) 1996-1999 David Muir Sharnoff. License hereby granted for anyone to use, 
# modify or redistribute this module at their own risk. 
#
# $Id: Util.pm,v 1.147 2014/12/03 08:40:26 hvn Exp $

package Radius::Util;
use Digest::MD5;
use Socket ();
use File::Path;
use File::Basename;
use Time::Local;
use POSIX ':signal_h';
use strict;

# This is the official Radiator version number:
$main::VERSION = '4.14';

# RCS version number of this module
$Radius::Util::VERSION = '$Revision: 1.147 $';

# For md5crypt
my $magic = '$1$';  # The prefix that signals an md5 password
my @itoa64 = split(//, 
'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');

# Temp variables, used by format_special
my (@time, @ptime, $ptime);

# Private arrays for date calculations
my @DoW         = qw(Sun Mon Tue Wed Thu Fri Sat);
my @DayOfWeek   = qw(Sunday Monday Tuesday Wednesday Thursday 
                     Friday Saturday);
my @MoY         = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my @MonthOfYear = qw(January February March April May June 
		     July August September October November December);

my %tzn_cache;

# These are the conversion functions for format_special
# Functions are called like ($p)
my %conversions =
    (
     '%', sub { '%' },
     'a', sub { return unless $_[0]->{rp}; 
		$_[0]->{rp}->getAttrByNum($Radius::Radius::FRAMED_IP_ADDRESS) },
     'c', sub { return unless $_[0] && defined $_[0]->{RecvFromAddress}; 
	      Radius::Util::inet_ntop($_[0]->{RecvFromAddress}) },
     'C', sub { return unless $_[0] && defined $_[0]->{RecvFromAddress}; 
		my $a = scalar &Radius::Util::gethostbyaddr($_[0]->{RecvFromAddress}); 
		return $a ? $a :  Radius::Util::inet_ntop($_[0]->{RecvFromAddress})},
     'D', sub { $main::config->{DbDir} },
     'h', sub { $main::hostname },
     'L', sub { $main::config->{LogDir} },
     'O', sub { return $main::farmInstance}, 
     'N', sub { return unless $_[0]; $_[0]->getNasId() },
     'n', sub { return unless $_[0]; $_[0]->getAttrByNum($Radius::Radius::USER_NAME) },
     'r', sub { "\n" },
     'R', sub { return unless $_[0]; my @n = split(/@/, $_[0]->getAttrByNum($Radius::Radius::USER_NAME)); $n[1] },
     'K', sub { return unless $_[0]; my ($realm) = $_[0]->getAttrByNum($Radius::Radius::USER_NAME) =~ /@([^@]*)$/; return $realm},
     
     'T', sub { return unless $_[0]; $_[0]->code },
     'U', sub { return unless $_[0]; my @n = split(/@/,
	  $_[0]->getAttrByNum($Radius::Radius::USER_NAME)); $n[0] },
     'u', sub { return unless $_[0]; $_[0]->{OriginalUserName} },
     'x', sub { return unless $_[0]; $_[0]->{EAPIdentity} },
     'X', sub { return unless $_[0]; my @n = split(/@/, $_[0]->{EAPIdentity}); $n[0] },
     'w', sub { return unless $_[0]; my @n = split(/@/, $_[0]->{OriginalUserName}); $n[0] },
     'W', sub { return unless $_[0]; my @n = split(/@/, $_[0]->{OriginalUserName}); $n[1] },
     'P', sub { return unless $_[0]; $_[0]->decodedPassword() },
     'z', sub { return unless $_[0]; Digest::MD5::md5_hex($_[0]->getAttrByNum($Radius::Radius::USER_NAME))},
     # This returns the NasIdentifier formatted as an string whose 
     # value is an integer like inet_aton. From Jerome Fleury <jeje@jeje.org>
     'I', sub { return unless $_[0]; my $ip = 0; map ($ip = $ip*256+$_, split('\.', $_[0]->getNasId() )); sprintf ('%u', $ip); },
     'Z', sub { return unless $_[0]; $_[0]->identifier },


     # From current time
     'B', sub {Radius::Util::strftime('%b %e, %Y %H:%M', time)}, 
     'G', sub {Radius::Util::strftime('%b %e, %Y %H:%M:%S', time)}, 
     'd', sub { @time = localtime(time) unless @time; sprintf("%02d", $time[3]) },
     'H', sub { @time = localtime(time) unless @time; sprintf("%02d", $time[2]) },
     'l', sub { scalar localtime(time)}, 
     'm', sub { @time = localtime(time) unless @time; sprintf("%02d", $time[4]+1); },
     'M', sub { @time = localtime(time) unless @time; sprintf("%02d", $time[1]) },
     's', sub { sprintf("%06d", (&getTimeHires)[1]) },
     'S', sub { @time = localtime(time) unless @time; sprintf("%02d", $time[0]) },
     't', sub { time },
     'y', sub { @time = localtime(time) unless @time; sprintf("%02d", $time[5] % 100); },
     'Y', sub { @time = localtime(time) unless @time; $time[5]+1900 }, # Correct Y2K behaviour for perl
     'q', sub { @time = localtime(time) unless @time; $DoW[$time[6]] },
     'Q', sub { @time = localtime(time) unless @time; $DayOfWeek[$time[6]] },
     'v', sub { @time = localtime(time) unless @time; $MoY[$time[4]] },
     'V', sub { @time = localtime(time) unless @time; $MonthOfYear[$time[4]] },

     # Times from Timestamp in the current packet (if any)
     'E', sub { $_[0] && $_[0]->{RecvTime} ? time - $_[0]->{RecvTime} : undef },
     'b', sub { $ptime },
     'A', sub { return unless $ptime; Radius::Util::strftime('%b %e, %Y %H:%M', $ptime)}, 
     'F', sub { return unless $ptime; Radius::Util::strftime('%b %e, %Y %H:%M:%S', $ptime)}, 
     'J', sub { return unless $ptime; Radius::Util::strftime('%Y-%m-%d %H:%M:%S', $ptime)}, 
     'o', sub { return unless $ptime; scalar localtime($ptime)}, 
     'e', sub { return unless $ptime; @ptime = localtime($ptime); sprintf("%02d", $ptime[5] % 100); },
     'f', sub { return unless $ptime; @ptime = localtime($ptime); $ptime[5] + 1900 }, # Correct Y2K behaviour for perl
     'g', sub { return unless $ptime; @ptime = localtime($ptime); sprintf("%02d", $ptime[4] + 1); },
     'i', sub { return unless $ptime; @ptime = localtime($ptime); sprintf("%02d", $ptime[3]) },
     'j', sub { return unless $ptime; @ptime = localtime($ptime); $ptime[2] },
     'k', sub { return unless $ptime; @ptime = localtime($ptime); $ptime[1] },
     'p', sub { return unless $ptime; @ptime = localtime($ptime); $ptime[0] },
     );

my %strftime_conversion = 
    (
     '%',	sub { '%' },
     'a',	sub { $DoW[$time[6]] },
     'A',	sub { $DayOfWeek[$time[6]] },
     'b',	sub { $MoY[$time[4]] },
     'B',	sub { $MonthOfYear[$time[4]] },
     'c',	sub { asctime_n(@time, '') },
     'd',	sub { sprintf("%02d", $time[3]); },
     'D',	sub { sprintf("%02d/%02d/%02d", $time[4]+1, $time[3], $time[5]%100) },
     'e',	sub { sprintf("%2d", $time[3]); },
     'h',	sub { $MoY[$time[4]] },
     'H',	sub { sprintf("%02d", $time[2]) },
     'I',	sub { sprintf("%02d", $time[2] % 12 || 12) },
     'j',	sub { sprintf("%03d", $time[7] + 1) },
     'k',	sub { sprintf("%2d", $time[2]); },
     'l',	sub { sprintf("%2d", $time[2] % 12 || 12) },
     'm',	sub { sprintf("%02d", $time[4]+1); },
     'M',	sub { sprintf("%02d", $time[1]) },
     'n',	sub { "\n" },
     'o',	sub { sprintf("%d%s", $time[3], (($time[3] < 20 && $time[3] > 3) ? 'th' : ($time[3]%10 == 1 ? "st" : ($time[3]%10 == 2 ? "nd" : ($time[3]%10 == 3 ? "rd" : "th"))))) },
     'p',	sub { $time[2] > 11 ? "PM" : "AM" },
     'r',	sub { sprintf("%02d:%02d:%02d %s", $time[2] % 12 || 12, $time[1], $time[0], $time[2] > 11 ? 'PM' : 'AM') },
     'R',	sub { sprintf("%02d:%02d", $time[2], $time[1]) },
     'S',	sub { sprintf("%02d", $time[0]) },
     't',	sub { "\t" },
     'T',	sub { sprintf("%02d:%02d:%02d", $time[2], $time[1], $time[0]) },
     'U',	sub { wkyr(0, $time[6], $time[7])},
     'w',	sub { $time[6] },
     'W',	sub { wkyr(1, $time[6], $time[7]) },
     'y',	sub { $time[5]%100 },
     'Y',	sub { $time[5]%100 + ( $time[5]%100<70 ? 2000 : 1900) },
     'x',	sub { sprintf("%02d/%02d/%02d", $time[4] + 1, $time[3], $time[5] % 100) },
     'X',	sub { sprintf("%02d:%02d:%02d", $time[2], $time[1], $time[0]) },
     'Z',	sub { &tz2zone(undef,undef,$time[8]) }
);

# Converts a month name into a 0 based month number
my %months  = 
    ( 
      'jan',       0,      'january',   0,
      'feb',       1,      'february',  1,
      'mar',       2,      'march',     2,
      'apr',       3,      'april',     3,
      'may',       4,
      'jun',       5,      'June',      5,
      'jul',       6,      'July',      6,
      'aug',       7,      'august',    7,
      'sep',       8,      'september', 8,
      'oct',       9,      'october',   9,
      'nov',      10,      'november', 10,
      'dec',      11,      'december', 11,
      );

# See if Time::HiRes is available
$Radius::Util::haveTimeHiRes = 0;
$Radius::Util::haveTimeHiRes = 1
    if eval {require Time::HiRes} ;

# Check if we need Socket6 for IPv6 support. If we do, we replace the
# functions with their Socket6 versions. They will also try to recover
# if Socket6 is missing completely.
unless (Radius::Util::get_ipv6_capability() eq 'core')
{
    require Radius::UtilSocket6;
    *Radius::Util::inet_pton = *Radius::UtilSocket6::inet_pton;
    *Radius::Util::inet_ntop = *Radius::UtilSocket6::inet_ntop;
    *Radius::Util::unpack_sockaddr_in = *Radius::UtilSocket6::unpack_sockaddr_in;
    *Radius::Util::pack_sockaddr_in = *Radius::UtilSocket6::pack_sockaddr_in;
    *Radius::Util::gethostbyaddr = *Radius::UtilSocket6::gethostbyaddr;
    *Radius::Util::pack_sockaddr_pton = *Radius::UtilSocket6::pack_sockaddr_pton;
    *Radius::Util::gethostbyname = *Radius::UtilSocket6::gethostbyname;
}

#####################################################################
# This is an implementation of Linux compatible MD5 password encryption
# A transliterations of crypt(pw, salt) in crypt.c in libcrypt
sub md5crypt
{
    my ($pw, $salt) = @_;

    # If the salt is in an encrypted password, then
    # extract the true salt from it
    $salt = $1 if ($salt =~ /\$1\$([^\$]{0,8})\$(.*)/);

    # Start with pw,magic,salt
    my $s1 = $pw . $magic . $salt;
    
    # Then just as many characters of the MD5(pw,salt,pw)
    my $final = Digest::MD5::md5($pw . $salt . $pw);

    my ($pl, $i, $s3);
    for ($pl = length($pw); $pl > 0; $pl -= 16)
    {
	$s1 .= substr($final, 0, $pl > 16 ? 16 : $pl);
    }

    # Then something really weird...
    for ($pl = length($pw); $pl; $pl >>=1)
    {
	$s1 .= substr($pl & 1 ? "\0" : $pw, 0, 1);
    }

    $final = Digest::MD5::md5($s1);
       
    # This algorithm is deliberately slow :-(
    for ($i = 0; $i < 1000; $i++)
    {
	$s3 = $i & 1 ? $pw : $final;

	$s3 .= $salt if $i % 3;
	$s3 .= $pw if $i % 7;
	$s3 .= $i & 1 ? $final : $pw;
	$final = Digest::MD5::md5($s3);
    }

    # Split $final into 16 bytes
    my @final = unpack('C16', $final);
    
    my $result = $magic . $salt . '$';
    # Convert groups of 3 bytes into 4 ascii chars
    $result .= &to64($final[0]<<16 | $final[6]<<8 | $final[12], 4);
    $result .= &to64($final[1]<<16 | $final[7]<<8 | $final[13], 4);
    $result .= &to64($final[2]<<16 | $final[8]<<8 | $final[14], 4);
    $result .= &to64($final[3]<<16 | $final[9]<<8 | $final[15], 4);
    $result .= &to64($final[4]<<16 | $final[10]<<8 | $final[5], 4);
    $result .= &to64($final[11], 2);

    return $result;
}

# Convert binary value into n chars from the set itoa64
sub to64
{
    my ($value, $n) = @_;

    my $result;
    while (--$n >= 0)
    {
	$result .= $itoa64[$value & 0x3f];
	$value >>= 6;
    }
    return $result;
}

#####################################################################
# Parse a date in the format Dec 04 1996, returns the time
# of midnight at the beginning of that day
sub parseDate
{
    my ($date) = @_;
    
    # print "parseDate: $date\n";
    # It would be really cool to use the DateParse module here
    # and accept lots of different formats (including relative)
    my ($second, $minute, $hour, $day, $mon, $year, $result);
    if ($date =~ /^\s*([A-Za-z]{3})\s*(\d{1,2}),?\s+(\d{2,4})\s*((\d{2}):(\d{2}):(\d{2}))?/)
    {
	# Mmm dd yy(yy) (hh:mm:ss)
	# Mmm dd, yy(yy) (hh:mm:ss)
	$mon = $months{lc $1};
	$year = $3;
	$day = $2;
	# Follow Perl standards for Y2K compliance
	$year -= 1900 if $year > 1900;
	$year += 100 if $year <= 37;
	# Dates way in the future are clamped to perls limit
	# of about 2037
	$year = 137 if $year > 137;
	($hour, $minute, $second) =  defined $7 ? ($5, $6, $7) : (0, 0, 0);
    }
    elsif ($date =~ /(\d{1,2})\s*([A-Za-z]{3}),?\s+(\d{2,4})\s*((\d{2}):(\d{2}):(\d{2}))?/)
    {
	# dd Mmm yy(yy) (hh:mm:ss)
	$mon = $months{lc $2};
	$year = $3;
	$day = $1;
	# Follow Perl standards for Y2K compliance
	$year -= 1900 if $year > 1900;
	$year += 100 if $year <= 37;
	# Dates way in the future are clamped to perls limit
	# of about 2037
	$year = 137 if $year > 137;
	($hour, $minute, $second) =  defined $7 ? ($5, $6, $7) : (0, 0, 0);
    }
    elsif ($date =~ /(\d{4})-(\d{2})-(\d{2})\s*((\d{2}):(\d{2}):(\d{2}))?/)
    {
	# yyyy-mm-dd (hh:mm:ss)
	$year = $1;
	# Follow Perl standards for Y2K compliance
	$year -= 1900 if $year > 1900;
	$year += 100 if $year <= 37;
	# Dates way in the future are clamped to perls limit
	# of about 2037
	$year = 137 if $year > 137;
	# Gag: FreeTDS has a bug that sometimes causes days == 0
	# eg, '12-31-1999 12:01:01.000' -> '2000-01-00 12:01:01',
	$day = $3;
	$day = 1 if $day <= 0;
	$mon = $2 - 1;
	($hour, $minute, $second) = defined $7 ? ($5, $6, $7) : (0, 0, 0);
    }
    elsif ($date =~ /(\d{2})[\/\.](\d{2})[\/\.](\d{2,4})\s*((\d{2}):(\d{2}):(\d{2}))?/)
    {
	# dd/mm/yy(yy) (hh:mm:ss)
	# dd.mm.yy(yy) (hh:mm:ss)
	$year = $3;
	# Follow Perl standards for Y2K compliance
	$year -= 1900 if $year > 1900;
	$year += 100 if $year <= 37;
	# Dates way in the future are clamped to perls limit
	# of about 2037
	$year = 137 if $year > 137;
	$day = $1;
	$mon = $2 - 1;
	($hour, $minute, $second) = defined $7 ? ($5, $6, $7) : (0, 0, 0);
    }
    elsif ($date =~ /\d{9,10}/)
    {
	# Unix epoch seconds integer
	return int $date;
    }
    else
    {
	&main::log($main::LOG_WARNING, "Bad date format: '$date'");
	return 0;
    }

    # $mon is not defined if bad month name was used
    unless (defined $mon)
    {
	main::log($main::LOG_WARNING, "Bad date format: '$date'");
	return 0;
    }
    $result = eval {Time::Local::timelocal($second, $minute, $hour, $day, $mon, $year);};
    &main::log($main::LOG_WARNING, "Bad date format: '$date': $@")
	if $@;

    return $result;
}

#####################################################################
# Convert an RFC 1123 date (GMT) into unix epoch seconds
sub parseDateRFC1123
{
    my ($date) = @_;

    if ($date =~ /(\d{1,2})\s*([A-Za-z]{3}),?\s+(\d{2,4})\s*((\d{2}):(\d{2}):(\d{2}))?/)
    {
	# dd Mmm yy(yy) (hh:mm:ss)
	my $mon = $months{lc $2};
	my $year = $3;
	my $day = $1;
	# Follow Perl standards for Y2K compliance
	$year -= 1900 if $year > 1900;
	$year += 100 if $year <= 37;
	# Dates way in the future are clamped to perls limit
	# of about 2037
	$year = 137 if $year > 137;
	my  ($hour, $minute, $second) =  defined $7 ? ($5, $6, $7) : (0, 0, 0);

	return eval {Time::Local::timegm($second, $minute, $hour, $day, $mon, $year);};
    }
    return; # Bad format
}

#####################################################################
# Parse a time in the format 22:11 or 9:05 AM, returns the seconds
# since midnight of the time
sub parseTime
{
    my ($time) = @_;

    if ($time =~ /(\d{1,2}):(\d{1,2})\s*(.*)/)
    {
	my ($hours, $mins, $meridian) = ($1, $2, $3);
	$hours += 12 if $meridian =~ /pm/i && $hours <= 11;
	$hours -= 12 if $meridian =~ /am/i && $hours == 12;
	return (($hours * 60) + $mins) * 60;
    }
    else
    {
	&main::log($main::LOG_WARNING, "Bad time format: '$time'");
	return 0;
    }
}

#####################################################################
# Format a string with a number of special replacements, useful for
# creating filenames at runtime.
# inspired by CTime.pm by David Muir Sharnoff <muir@idiom.com>.
# $self is an optional pointer to an SqlDb subclass for quoting
# @extras will be available as %0, %1 etc
# formatter functions wil be called like ($attrname, $p)
my %formatters =
(
 Special  => sub {&{$conversions{$_[0]}}($_[1])},
 Quote    => sub {return $_[2]->quote($_[0])}, # For SQL quoting
 GlobalVar  => sub {return &main::getVariable($_[0])},
 # Attribute from the current request: Note special case for where formatter is not specified
 Request    => sub {return $_[1] ? $_[1]->get_attr($_[0]) : ''},
 ''         => sub {return $_[1] ? $_[1]->get_attr($_[0]) : ''},
 # Attribute in the outer request for tunneled auths
 OuterRequest => sub {return $_[1] && $_[1]->{outerRequest} ? 
			  $_[1]->{outerRequest}->get_attr($_[0]) : ''},
 # Attribute from the current reply:
 Reply      => sub {return $_[1]->{rp} ? $_[1]->{rp}->get_attr($_[0]) : ''},
 # Variable from the Client clause
 Client     => sub {return $_[1] ? $_[1]->{Client}{$_[0]} : ''},
 # Variable from the Handler clause
 Handler    => sub {return $_[1] ? $_[1]->{Handler}{$_[0]} : ''},
 # Variable from the latest AuthBy clause
 AuthBy    => sub {return $_[1] ? $_[1]->{AuthBy}{$_[0]} : ''},
 # Variable from the main ServerConfig
 Server    => sub {return $main::config->{$_[0]}},
 # An attribute forced to its integer value:
 IntegerVal => sub {return $_[1] ? $_[1]->{Dict}->valNameToNum($_[0], $_[1]->get_attr($_[0])) : '0'},
 # IPV4 address attribute or value as hex:
 HexAddress => sub {my $ip = $_[0]; 
		    $ip = $_[1]->get_attr($_[0]) if $_[1] && $ip !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/; 
		    return $_[1] ? join('', map {sprintf "%02X", $_} split(/\./, $ip)) : ''},
 SQL        => sub { my $value = $_[0];
		     if ($_[0] =~ /^(.*?):(.*)/)
		     {
			 require Radius::SqlDb;
			 my ($identifier, $query) = ($1, $2);
			 my $db = &Radius::Configurable::find('AuthBy', $identifier);
			 if ($db)
			 {
			     ($value) = $db->queryOneRow($query);
			 }
			 else
			 {
			     &main::log($main::LOG_ERR, "Could not find SQL clause '$identifier' to query special value with $value");
			 }
		     }
		     return $value;
                },
);
# New version for improved performance and extensibility
sub format_special
{
    my ($s, $p, $self, @extras) = @_;

    # Some unusual constructs here cause warnigns with -w
#    no warnings "uninitialized";
    $s = '' unless defined $s; # Prevent other warnings

    # Global variables so the conversion and formatting functions will see them
    @time = @ptime = ();
    $ptime   = $p ? $p->get_attr('Timestamp') : undef;

    # Need to convert single character % formats _and_ positional args all
    # in one go, else may get unpleasant interactions, especially when the
    # the resulting string contains a %
    no warnings qw(uninitialized);
    $s =~ s/%([%aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTUuvVwWxXyYzZ]|\d+)/$1 =~ m@(^\d+)@ ? $extras[$1] : &{$conversions{$1}}($p)/egs;

    # Something that looks like %{xxx} or %{xxx:yyy}
    # %{nnn} is assumed to be the same as %{Request:xxx}
    # Permit nested %{x:y} contructs, such as %{x:%{y:z}}
    my $matched;
    do 
    {
	$matched = 0;
	$s =~ s/%\{(([^:\}]+):)?(?!.*\%\{)(.*?)\}/$matched++;exists $formatters{$2} ? &{$formatters{$2}}($3, $p, $self) : ''/egs;
    } while $matched; 

#    print "returning $s\n";
    return $s;
}

#####################################################################
# Format a date/time using conventional strftime
# conversions
sub tz2zone
{
    my($TZ, $time, $isdst) = @_;

    $TZ = defined($ENV{'TZ'}) ? ( $ENV{'TZ'} ? $ENV{'TZ'} : 'GMT' ) : ''
	unless $TZ;

    # Hack to deal with 'PST8PDT' format of TZ
    # Note that this can't deal with all the esoteric forms, but it
    # does recognize the most common: [:]STDoff[DST[off][,rule]]
    
    if (! defined $isdst) {
	my $j;
	$time = time() unless $time;
	($j, $j, $j, $j, $j, $j, $j, $j, $isdst) = localtime($time);
    }
    
    if (defined $tzn_cache{$TZ}->[$isdst]) {
	return $tzn_cache{$TZ}->[$isdst];
    }
    
    if ($TZ =~ /^
	( [^:\d+\-,] {3,} )
	( [+-] ?
	  \d {1,2}
	  ( : \d {1,2} ) {0,2} 
	  )
	( [^\d+\-,] {3,} )?
	/x
	) {
	$TZ = $isdst ? $4 : $1;
	$tzn_cache{$TZ} = [ $1, $4 ];
    } else {
	$tzn_cache{$TZ} = [ $TZ, $TZ ];
    }
    return $TZ;
}

sub asctime_n {
    my($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst, $TZname) = @_;
    $year += ($year < 70) ? 2000 : 1900;
    $TZname .= ' ' 
	if $TZname;
    sprintf("%s %s %2d %2d:%02d:%02d %s%4d",
	  $DoW[$wday], $MoY[$mon], $mday, $hour, $min, $sec, $TZname, $year);
}

sub wkyr 
{
    my($wstart, $wday, $yday) = @_;
    $wday = ($wday + 7 - $wstart) % 7;
    return int(($yday - $wday + 13) / 7 - 1);
}

sub strftime 
{			
    my ($template, $time) = @_;

    $time ||= time; # Defaults to current time
    @time = localtime($time);
    $template =~ s/%([%aAbBcdDehHIjklmMnopQrRStTUwWxXyYZ])/&{$strftime_conversion{$1}}()/egs;

    return $template;
}

#####################################################################
# Write details of an accounting packet to a file
# $acctFileName is modified by special formatting
# $dummy is an historical artifact
# $format_hook is a reference to an anonymous subroutine that takes
#              no arguments and returns the formatted log entry
sub logAccounting
{
    my ($p, $dummy, $acctFileName, $format, $format_hook) = @_;

    my $filename = &format_special($acctFileName, $p);

    # Permit pipes
    if ($filename !~ /^\|/)
    {
	# Make sure the log file directory exists. mkpath can die
	eval {mkpath(dirname($filename), 0, 0755)}
	unless -d dirname($filename);
	$filename = ">>$filename";
    }

    open(LOG, $filename)
	|| &main::log($main::LOG_ERR, "Could not open accounting log file '$filename': $!", $p);
	    
    # This is where the packet is formatted into the log file.
    # If you want a different accounting log file format, you can
    # change this bit
    if (defined $format_hook)
    {
	# Format using a subref
	print LOG &$format_hook(),"\n";
    }
    elsif (defined $format)
    {
	# Format for accounting log file
	print LOG &format_special($format, $p),"\n";
    }
    else
    {
	# No special format, do it in the standard radius log file
	# format
	print LOG scalar localtime(time) . "\n" . $p->format . "\n";
    }
    
    close(LOG)
	|| &main::log($main::LOG_ERR, "Could not close accounting log file '$filename': $!", $p);
}

#####################################################################
# Compute a Hashed Message Authentication Code
# As per RFC2085, ftp://ftp.isi.edu/in-notes/rfc2085.txt
# basically MD5(K ^ opad, MD5(K ^ ipad), text)
# REVISIT: use the one in Digest-MD5 instead soon
sub hmac_md5
{
    my ($K, $text) = @_;

    my $ipad = chr(0x36) x 64;
    my $opad = chr(0x5c) x 64;

    # (1) append zeros to the end of K to create a 64 byte string
    #    (e.g., if K is of length 16 bytes it will be appended with 48
    #    zero bytes 0x00)
    if (length $K > 64)
    {
	$K = Digest::MD5::md5($K);
    }
    else
    {
	$K .= chr(0) x (64 - length($K));
    }

    # (2) XOR (bitwise exclusive-OR) the 64 byte string computed in 
    # step (1) with ipad
    my $x = $K ^ $ipad;

    # (3) append the data stream 'text' to the 64 byte string resulting
    #    from step (2)
    $x .= $text;

    # (4) apply MD5 to the stream generated in step (3)
    $x = Digest::MD5::md5($x);

    # (5) XOR (bitwise exclusive-OR) the 64 byte string computed in
    #    step (1) with opad
    my $y = $K ^ $opad;

    # (6) append the MD5 result from step (4) to the 64 byte string
    #    resulting from step (5)
    $y .= $x;

    # (7) apply MD5 to the stream generated in step (6) and output
    #    the result
    return Digest::MD5::md5($y);
}

#####################################################################
# Append a single line of text to a file.
# Current implementation opens, writes and closes
# Future implementations might hold the file open, and reopen on
# signal, or perhaps pipe to a daemon
# Return true if successful
sub append
{
    my ($filename, $line) = @_;

    # Make sure the files directory exists, unless its a pipe
    if ($filename !~ /^\|/)
    {
	# mkpath can die
	eval {mkpath(dirname($filename), 0, 0755)}
	    unless -d dirname($filename);
	$filename = ">>$filename";
    }

    open(FILE, $filename) || return;
    print FILE $line;
    close(FILE) || return;
    return 1;
}

#####################################################################
# On platforms that support it, and when timeout is
# non-zero, execute the sub with a timeout.
# Dies with error 'timeout' of the timeout expires
sub exec_timeout
{
    my ($timeout, $code) = @_;

    # Sigh, need better signal handling with later perls
    # as per http://search.cpan.org/~lbaxter/Sys-SigAction/dbd-oracle-timeout.POD
    if ($^O eq 'MSWin32' || !$timeout)
    {
	#Windows not timeouts supported, just run the code inside an eval
	# in case the DBD/DBI croaks
	eval { &$code(); };
    }
    elsif ($] >= 5.008)
    {
	# Perl 5.8
	my $mask = POSIX::SigSet->new(SIGALRM); #list of signals to mask in the handler
	my $action = POSIX::SigAction->new(sub { die "timeout" ; }, $mask );
	my $oldaction = POSIX::SigAction->new();
	sigaction(&POSIX::SIGALRM, $action, $oldaction );
	eval 
	{
	    alarm($timeout);
	    &$code();
	};
	alarm(0); # Cancel the alarm
	sigaction(&POSIX::SIGALRM, $oldaction); #restore original signal handler
    }
    else
    {
	# Perl 5.6
	eval
	{
	    local $SIG{ALRM} = sub {die "timeout"};
	    alarm($timeout);
	    
	    &$code();
	    
	};
	alarm(0); # Cancel the alarm
    }
}

#####################################################################
# Initialize the random number system
# From Programming perl p 223
sub seed_random
{
    srand(time() ^ ($$ + ($$ << 15)));
}

#####################################################################
# Generate a random binary string $l octets long
sub random_string
{
    my ($l) = @_;

    my $ret;
    for (1 .. $l)
    {
	$ret .= chr(rand(256));
    }
    return $ret;
}

#####################################################################
# Take a comma separated list of attr=val and split it up
# into an array ([attr, val], [attr, val], ....)
sub splitAttrVals
{
    my ($s) = @_;

    my @ret;

    $s =~ s/^\s*//; # Strip leading white space
    $s =~ s/\s*$//; # Strip trailing white space
    $s =~ s/^,*//;  # Strip redundant leading commas
    while ($s ne '')
    {
	if ($s =~ /^([^ =]+) *= *"((\\"|[^"])*)",*/g)
	{
	    # Quoted value
	    my ($attr, $value) = ($1, $2);
	    $value =~ s/\\"/"/g; # Unescape quotes
	    $value =~ s/\\(\d{3})/chr(oct($1))/ge; # Convert escaped octal
	    push(@ret, [ $attr, $value ]);
	    $s = substr($s, pos $s);
	}
	elsif ($s =~ /^([^ =]+) *= *([^,]*),*/g)
	{
	    # Unquoted value
	    push(@ret, [ $1, $2 ]);
	    $s = substr($s, pos $s);
	}
	else
	{
	    &main::log($main::LOG_ERR, "Bad attribute=value pair: $s");
	    last;
	}
	$s =~ s/^\s*//; # Strip leading white space
    }
    return @ret;
}

#####################################################################
# Convert a numeric or symbolic UDP port into a port number
sub get_port
{
    my ($p, $protocol) = @_;

    $protocol = 'udp' unless defined $protocol;
    $p = &Radius::Util::format_special($p);
    if ($p =~ /^\d+$/)
    {
	# Completely numeric, 0 is permitted
	return $p;
    }
    else
    {
	my $ret = getservbyname($p, $protocol);
	&main::log($main::LOG_WARNING, "Unknown service name $p")
	    unless $ret;
	return $ret;
    }
}

#####################################################################
# Return true iff $p is a valid IP V4 address
sub isIP4Address
{
    my ($s) = @_;

    return $s =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
	&& $1 < 256 && $2 < 256 && $3 < 256 && $4 < 256;
}

#####################################################################
# Replicate the MYSQL  password hashing algorithm
sub mysqlPassword
{
    my ($pw) = @_;

    my $nr = 1345345333;
    my $add = 7;
    my $nr2 = 0x12345671;
    $pw =~ s/[ \t]//g; # Strip spaces and tabs
    map {
	$nr ^= (((($nr & 63)+$add)*$_) + ($nr << 8));
	$nr &= 0x7fffffff;
	$nr2 += (($nr2 << 8) ^ $nr);
	$nr2 &= 0x7fffffff;
	$add += $_;
    } unpack('C*', $pw);

    return sprintf ('%08lx%08lx', $nr, $nr2);
}

#####################################################################
# Convert IPV4 or IPV6 addresses from presentation to packed network addresses
# IPV6 addresses are recognised by a leading 'ipv6:' (case insensitive)
# examples:
# 127.0.0.1    IPV4 localhost
# ipv6:::1     IPV6 localhost
sub inet_pton
{
    my ($a) = @_;

    if ($a =~ /^ipv6:/i || $a =~ /^[0-9a-fA-F:]+$/ || $a =~ /^::ffff:/i)
    {
	my ($sockaddr, $family) = Radius::Util::pack_sockaddr_pton(undef, $a);
	return unless $sockaddr;
	my (undef, $addr) = Socket::unpack_sockaddr_in6($sockaddr);
	return $addr;
    }
    else
    {
	return Socket::inet_aton($a);
    }
}

#####################################################################
# Convert IPV4 or IPV6 addresses from packed network to presentation addresses
# Silly lengths result in undef (Socket routines can crash otherwise)
sub inet_ntop
{
    my ($a) = @_;

    return unless length $a;
    if (length $a == 16)
    {
	# IPV6. The port does not matter but was required by Windows XP
	my $sockaddr = Socket::pack_sockaddr_in6(1812, $a);
	my ($err, $p) = Socket::getnameinfo($sockaddr,
					    Socket::NI_NUMERICHOST() |
					    Socket::NI_NUMERICSERV());
	return if $err;
	# Short circuit for IPV4 addresses received over IPV6
	return $1 if ($p =~ /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
	return $p;
    }
    elsif (length $a == 4)
    {
	# IPV4
	return Socket::inet_ntoa($a); 
    }
    else
    {
	return;
    }
}

#####################################################################
# Unpack sockaddr_in or sockaddr_in6 structure
sub unpack_sockaddr_in
{
    my ($a) = @_;

    if (length $a > 16)
    {
	# IPV6
	return Socket::unpack_sockaddr_in6($a); 
    }
    elsif (length $a == 16)
    {
	return Socket::unpack_sockaddr_in($a);
    }
    else
    {
	return;
    }
}

#####################################################################
# $a is a packed IPV4 or V6 address
sub pack_sockaddr_in
{
    my ($p, $a) = @_;

    if (length $a > 4)
    {
	return Socket::pack_sockaddr_in6($p, $a);
    }
    else
    {
	return Socket::pack_sockaddr_in($p, $a);
    }
}

#####################################################################
# Convert a host name or address into a packed portaddress and protocol family
# $name is an ASCII name or address, perhaps with a leading 'ipv6:'
# Return (sockaddr_in or sockaddr_in6, protocol/address family)
sub pack_sockaddr_pton
{
    my ($port, $name, $sock_type) = @_;

    if ($name =~ /ipv6:(.*)/i || $name =~ /(^.*:.*$)/) # Covers also ^::ffff:.*
    {
	# Hint was required by some Solaris version of getaddrinfo:
	$sock_type = Socket::SOCK_STREAM() unless defined $sock_type;
	my ($err, @res) = Socket::getaddrinfo($1, $port,
					      {family => Socket::AF_INET6(),
					       socktype => $sock_type});
	return if $err; # Unresolved or other failure
	# getaddrinfo returns addr as a sockaddr_in6
	return ($res[0]->{addr}, $res[0]->{family})
	    if defined $res[0];
    }
    else
    {
	# IPV4
	my ($cname, $aliases, $addrtype, $length, $address) = gethostbyname($name);
	# Nothing in the DNS?, try to convert from presentation to network
	$address = Radius::Util::inet_pton($name)
	    unless defined $address;
	return (Socket::pack_sockaddr_in($port, $address), Socket::PF_INET())
	    if defined $address;
    }
    return;
}

#####################################################################
# Get info about an IPV4 or IPV6 name
# returns ($cname, $aliases, $addrtype, $length, @addrs)
# For IPv6 currently returns just one address.
sub gethostbyname
{
    my ($name) = @_;

    if ($name =~ /ipv6:(.*)/i || $name =~ /(^.*:.*$)/)
    {
	# Use SOCK_RAW to limit number of returned addresses
	my ($err, @res) = Socket::getaddrinfo($1, undef,
					      {socktype => Socket::SOCK_RAW(),
					       family => Socket::AF_INET6(),
					       flags => Socket::AI_CANONNAME()});
	return if $err; # Unresolved
	return unless $res[0]; # Is this possible?

	my $cname = $res[0]->{canonname} ? $res[0]->{canonname} : $name;
	my (undef, $addr) = Socket::unpack_sockaddr_in6($res[0]->{addr});

	return ($cname, '', Socket::AF_INET6(), length ($addr), $addr);
    }

    # IPV4
    return gethostbyname($name);
}

#####################################################################
# $addr is a packed binary address
sub gethostbyaddr
{
    my ($addr) = @_;

    return gethostbyaddr($addr, Socket::AF_INET()) if length $addr == 4;
    return gethostbyaddr($addr, Socket::AF_INET6());
}

#####################################################################
# Send mail. IF there are errors, return a non-empty error message
sub sendMail
{
    my ($server, $from, $to, $subject, $text) = @_;

    eval{require Net::SMTP;};
    return "Could not load Net::SMTP module for sending email: $@" if $@;

    my $smtp = Net::SMTP->new($server);
    return "Net::SMTP new failed: $!" unless $smtp;
    $smtp->mail($from);
    return "Net::SMTP mail failed: " . $smtp->message() unless $smtp->ok();
    $smtp->to($to);
    return "Net::SMTP to failed: " . $smtp->message() unless $smtp->ok();
    $smtp->data();
    return "Net::SMTP data failed: " . $smtp->message() unless $smtp->ok();
    $smtp->datasend("To: $to\nSubject: $subject\n\n$text");
    return "Net::SMTP datasend failed: " . $smtp->message() unless $smtp->ok();
    $smtp->dataend();
    return "Net::SMTP dataend failed: " . $smtp->message() unless $smtp->ok();
    $smtp->quit;
    return "Net::SMTP quit failed: " . $smtp->message() unless $smtp->ok();
    return;
}

#####################################################################
# Encapsulate the rand function, mainly so we can control it during testing,
# since Unix and Windows have different random number gens
sub rand
{
    return rand($_[0]);
}

#####################################################################
sub save_backup
{
    my ($filename) = @_;

    my $newname = $filename . '.bak';
    return rename($filename, $newname);
}

#####################################################################
# Print a time interval in easy to read format
# $secs is unsigned
sub formatInterval
{
    my ($secs) = @_;

    my $days = int($secs / 86400);
    my $hours = int($secs / 3600) % 24;
    my $mins = int($secs / 60) % 60;
    my $seconds = $secs % 60;
    return sprintf('%dd %dh %dm %ds', $days, $hours, $mins, $seconds);
}

#####################################################################
# Diameter Time uses NTP format (seconds from 1 Jan 1900)
# Convert between NTP date to unix epoc time. Value got from RFC 868
sub ntptime2systime { return $_[0] - 2208988800 };
sub systime2ntptime { return $_[0] + 2208988800 };


#####################################################################
# If time Hires is available return the current time and micros,
# else return the current time and 0 micros
sub getTimeHires
{
    return $Radius::Util::haveTimeHiRes ? &Time::HiRes::gettimeofday() : (time, 0);
}

#####################################################################
# Return the time interval between 2 pairs of secs,micros in floating seconds
# secs1, micros1, secs2, micros2
sub timeInterval
{
    return ($_[2] - $_[0]) + (($_[3] - $_[1]) / 1_000_000);
}

#####################################################################
# Probe runtime environment's IPv6 capabilities. Return one of (core,
# socket6 or none).
sub get_ipv6_capability
{
    # See if we already know the capability.
    my $value = $main::ipv6_capability;
    return $value if defined $value;

    # If something dies, value remains undefined
    eval
    {
	# Prepare some test data
	my $port = 1812;
	my $addr = '2001:db8:148:100::31';
	my $prepared_addr = pack('H*', '20010db8014801000000000000000031');

	# First create a sockaddr_in6
	my ($err, @res) = Socket::getaddrinfo($addr, $port,
					      {family => Socket::AF_INET6(),
					       socktype => Socket::SOCK_STREAM()});
	die if $err;
	my $sa = $res[0]->{addr};

	# Try to unpack it back to port and address
	my ($err2, $addr2, $port2) = Socket::getnameinfo($sa,
							 Socket::NI_NUMERICHOST() |
							 Socket::NI_NUMERICSERV());
	die if $err2;

	# We should get back the original port and address.
	# Note: this depends on textual address presentation.
	die unless ($port == $port2 && $addr eq lc $addr2);

	# Then see if we can unpack a sockaddr_in6
	my (undef, $packed_sa_addr) = Socket::unpack_sockaddr_in6($sa);
	die unless $packed_sa_addr eq $prepared_addr;

	# Create another sockaddr_in6 from a prepared address
	my $sa2 = Socket::pack_sockaddr_in6($port, $prepared_addr);

	# Both sockaddr_in6 structures should be equal
	die unless ($sa eq $sa2);

	$value = 'core';
    };

    # Core did not provide everything required. Try Socket6.
    eval
    {
	require Socket6;
	$value = 'socket6';
    } unless $value;

    $value = 'none' unless $value;
    $main::ipv6_capability = $value;
    return $main::ipv6_capability;
}

1;

