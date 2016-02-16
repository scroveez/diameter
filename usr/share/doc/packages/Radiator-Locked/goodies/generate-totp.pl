#!/usr/bin/env perl
#
# generate-totp.pl
#
# Simple script for generating secret values for TOTP and printing
# them in different text formats and as QR code images.
#
# $Id: generate-totp.pl,v 1.1 2014/11/13 20:31:27 hvn Exp $

use Radius::Util;
use strict;
use warnings;
use MIME::Base32 qw(RFC);
use Imager::QRCode qw(plot_qrcode);
#use Imager::FILE::GIF;

use Getopt::Long;
my $accountname='test';
my $issuer='Radiator';
my $algorithm='SHA1';
my $hex_secret;
my $image_format = 'gif';  # Note: bmp may work without external Imager::FILE::.. modules
my $digits=6;
my $period=30;
my $qrcode_path='.';
my @options = (
               'h' => \&usage,                    # Help, show usage
               'accountname=s' => \$accountname,  # OTP Account Name
               'issuer=s' => \$issuer,            # OTP Issuer
               'algorithm=s' => \$algorithm,      # Algorithm: SHA1, SHA256, or SHA512
               'digits=i' => \$digits,
               'period=i' => \$period,
               'hex_secret=s' => \$hex_secret,  # Hex encoded secret
               'image_format=s' => \$image_format,
               'qrcode_path=s' => \$qrcode_path,
               );

GetOptions(@options) || usage();

usage() if $algorithm ne 'SHA1' && $algorithm ne 'SHA256' && $algorithm ne 'SHA512';
usage() if $digits != 6 && $digits != 8;

my $random_hexstring ='';
$random_hexstring = unpack('H*', Radius::Util::random_string(20)) if $algorithm eq 'SHA1' ;
$random_hexstring = unpack('H*', Radius::Util::random_string(32)) if $algorithm eq 'SHA256';
$random_hexstring = unpack('H*', Radius::Util::random_string(64)) if $algorithm eq 'SHA512';
$random_hexstring = $hex_secret if $hex_secret;
print "TOTP key to insert into Radiator database: $random_hexstring\n";

my $random_base32string = MIME::Base32::encode(pack("H*", $random_hexstring));

$random_base32string =~ s/(.{4})/$1 /g;  # Add spaces
$random_base32string =~ s/ $//;          # Remove trailing space

print "TOTP key in BASE32 for client: $random_base32string\n";

my $img_file = "$qrcode_path/$issuer" . "_$accountname.$image_format";
print "Writing QR code file $img_file\n";

# This will die if the appropriate Imager::FILE::... module is not
# available. Try bmp if you do not wish to install additional modules.
#
my $img = plot_qrcode("otpauth://totp/$issuer:$accountname?secret=$random_base32string&issuer=$issuer&algorithm=$algorithm&digits=$digits&period=$period");
$img->write(file => $img_file) or die "Cannot write $img_file: " . $img->errstr . "\n";

#####################################################################
sub usage
{
    print "usage: $0 [-accountname accountname] [-issuer issuer] [-algorithm SHA1|SHA256|SHA512]
		[hex_secret string] [-digits 6|8] [-period period] [image_format gif|bmp|jpeg|..] [-qrcode_path imagepath]\n";
    exit;
}
