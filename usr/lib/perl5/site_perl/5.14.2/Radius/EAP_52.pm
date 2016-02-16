# EAP_52.pm
#
# Module for  handling Authentication via EAP type 52
# (EAP-PWD)
# Requires Crypt-OpenSSL-EC, Crypt-OpenSSL-Bignum and OpenSSL
#
# Complies with RFC 5931
# The mandatory parameters from 2.10. Mandatory-to-Implement Parameters
# are impelmented except that D-H groups 19, 20, 21, 25, 26 are all supported.
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2012 Open System Consultants
# $Id: EAP_52.pm,v 1.7 2013/07/03 14:22:42 hvn Exp $

package Radius::EAP_52;
use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum;
use strict;

# RCS version number of this module
$Radius::EAP_52::VERSION = '$Revision: 1.7 $';

# Masks for L and M bits and opcode mask
$Radius::EAP_52::L_bit                  = 0x80;
$Radius::EAP_52::M_bit                  = 0x40;
$Radius::EAP_52::PWD_EXCH_MASK          = 0x3f;

# OPCodes for PWD-Exch
$Radius::EAP_52::PWD_EXCH_RESERVED      = 0x00;
$Radius::EAP_52::PWD_EXCH_ID            = 0x01;
$Radius::EAP_52::PWD_EXCH_COMMIT        = 0x02;
$Radius::EAP_52::PWD_EXCH_CONFIRM       = 0x03;

# Group Description field
# taken from the IANA registry for
# "Group Description" created by IKE [RFC2409].
$Radius::EAP_52::GROUP_X9_62_prime256v1 = 19; # 256-bit random ECP group 
$Radius::EAP_52::GROUP_secp384r1        = 20; # 384-bit random ECP group
$Radius::EAP_52::GROUP_secp521r1        = 21; # 521-bit random ECP group
$Radius::EAP_52::GROUP_X9_62_prime192v1 = 25; # 192-bit Random ECP Group
$Radius::EAP_52::GROUP_secp224r1        = 26; # 224-bit Random ECP Group

# NIDs for the various group descriptions
# from openssl/obj_mac.h
$Radius::EAP_52::NID_X9_62_prime256v1   = 415; # 256-bit random ECP group 
$Radius::EAP_52::NID_secp384r1          = 715; # 384-bit random ECP group
$Radius::EAP_52::NID_secp521r1          = 716; # 521-bit random ECP group
$Radius::EAP_52::NID_X9_62_prime192v1   = 409; # 192-bit Random ECP Group
$Radius::EAP_52::NID_secp224r1          = 713; # 224-bit Random ECP Group

# Random Function field values
$Radius::EAP_52::PREF_RANDOM_RFC5931    = 0x01;

# PRF field values
$Radius::EAP_52::PRF_HMAC_SHA256        = 0x01;

# Prep field values
$Radius::EAP_52::PREP_NONE              = 0x00;
$Radius::EAP_52::PREP_RFC2759           = 0x01;
$Radius::EAP_52::PREP_SASLprep          = 0x02;

# input is a group description number, prob one of $Radius::EAP_52::GROUP_*
# output is NID, one of $Radius::EAP_52::NID_*
# else undef
sub group_description_to_NID
{
    my ($group) = @_;

    return $Radius::EAP_52::NID_X9_62_prime256v1 if $group == $Radius::EAP_52::GROUP_X9_62_prime256v1;
    return $Radius::EAP_52::NID_secp384r1        if $group == $Radius::EAP_52::GROUP_secp384r1;
    return $Radius::EAP_52::NID_secp521r1        if $group == $Radius::EAP_52::GROUP_secp521r1 ;
    return $Radius::EAP_52::NID_X9_62_prime192v1 if $group == $Radius::EAP_52::GROUP_X9_62_prime192v1;
    return $Radius::EAP_52::NID_secp224r1        if $group == $Radius::EAP_52::GROUP_secp224r1;
    return; # Unrecognised
}

#####################################################################
# Called by EAP.pm when the caller wants to know the EAP type name this class supports
sub type_name
{
    my ($classname) = @_;

    return 'PWD';
}

#####################################################################
# request
# Called by EAP.pm when a request is received for this protocol type
sub request
{
    my ($classname, $self, $context, $p, $data) = @_;

    return $self->eap_error('Unexpected EAP request');
}

#####################################################################
# Called by EAP.pm when an EAP Response/Identity is received
sub response_identity
{
    my ($classname, $self, $context, $p) = @_;

    # Send EAP-pwd-ID/Request
    # with Ciphersuite, Token, Password Processing Method, Server_ID

    # group description is from IKE [RFC2409].
    my $group_num = $Radius::EAP_52::GROUP_X9_62_prime256v1;
    my $random_function = $Radius::EAP_52::PREF_RANDOM_RFC5931;
    my $prf = $Radius::EAP_52::PRF_HMAC_SHA256;
    my $token = Radius::Util::random_string(4);
    my $prep = $Radius::EAP_52::PREP_NONE;
    my $identity = $main::hostname;
    my $pwdid = pack('n C C a4 C a*',
		     $group_num,
		     $random_function,
		     $prf,
		     $token,
		     $prep,
		     $identity);
    $context->{token} = $token;

    $context->{state} = 'PWD_ID_Response';
    return eap_pwd_send($self, $context, $p, $Radius::EAP_52::PWD_EXCH_ID, $pwdid);
}

#####################################################################
# REVISIT: be consistent with section 2.7.2. Passwords if prep fails
sub prep_password
{
    my ($self, $password, $algorithm) = @_;

    if ($algorithm == $Radius::EAP_52::PREP_NONE)
    {
	# No prep
    }
    else
    {
	$self->log($main::LOG_ERR, "EAP-PWD prep algorithm $algorithm not implemented");
    }
    return $password;
}

#####################################################################
# counter-based KDF based on NIST SP800-108
# per RFC 5931 section 2.5
# returns the key, valid to $resultbitlen bits
sub KDF
{
    my ($key, $label, $resultbitlen) = @_;

    my $resultbytelen = ($resultbitlen + 7) >> 3; # Number of bytes required

    my $len = 0; # Number of bytes generated so far
    my $i = 1;
    my $L = $resultbitlen;
    my $result = '';
    my $K_i = '';
    while ($len < $resultbytelen)
    {
	$K_i = Digest::SHA::hmac_sha256($K_i . pack('n', $i++) . $label . pack('n', $L), $key);
	$result .= $K_i;
	$len += 32; # SHA256_DIGEST_LENGTH
    }
    # REVISIT: mask off the excess?
    return $result;
}


#####################################################################
# The random function H(x) = HMAC-SHA256(0^32, x)
# This is the default and minimum requirement
sub H
{
    my ($x) = @_;

    return Digest::SHA::hmac_sha256($x, pack('x32'));
}

#####################################################################
# Compute a 'random'  secret point on an elliptic curve based
# on the password and identities.
# Uses group, prime, order, cofactor already caclulated in $context
# Returns pwe
sub compute_pwe
{
    my ($self, $context, $group_num, $password, $server_id, $peer_id, $token) = @_;

    my $primebitlen = $context->{prime}->num_bits();
    my $pwe = Crypt::OpenSSL::EC::EC_POINT::new($context->{group});
    return unless $pwe;

    my $ctr = 0;
    while (1)
    {
	# Max number of candidates to test in hunt-and-pack
	# 30 Should be enough? 10 fails every 1000 or so attempts
	# and 20 fails every 20,000 or so. Whats the best way to determine this number?
	if ($ctr++ > 30) 
	{
	    $self->log($main::LOG_ERR, "EAP-PWD too many attempts to find random point on curve for group $group_num");
	    return;
	}

	# compute counter-mode password value and stretch to prime
	# pwd-seed = H(token | peer-id | server-id | password | counter)
	my $pwe_digest = H($token . $peer_id . $server_id . $password . pack('C', $ctr));
	my $pwd_value = KDF($pwe_digest, 'EAP-pwd Hunting And Pecking', $primebitlen);

	# Convert $pwd_value to a BIGNUM
	my $candidate = Crypt::OpenSSL::Bignum->new_from_bin($pwd_value);
	# If primebitlen is not a multiple of 8, need to shift right
	# by the number of unneeded bits
	if ($primebitlen % 8)
	{
	    $candidate->rshift(8 - ($primebitlen % 8));
	}

	# from RFC 5931 Section 2.8.3:
	# If the pwd-value is greater than or equal to the prime, p, the
	# counter is incremented, and a new pwd-seed is generated and the
	# hunting-and-pecking continues.  If pwd-value is less than the prime,
	# p, it is passed to the group-specific operation which either returns
	# the selected Password Element or fails.  If the group-specific
	# operation fails, the counter is incremented, a new pwd-seed is
	# generated, and the hunting-and-pecking continues.  This process
	# continues until the group-specific operation returns the Password
	# Element.

	# Dont use it if its greater than or equal to the prime
	next if $candidate->ucmp($context->{prime}) >= 0;

	# ECC Operation for PWE: section 2.8.3.1
	my $rnd = Crypt::OpenSSL::Bignum->new_from_bin($pwe_digest);
	my $is_odd = $rnd->is_odd() ? 1 : 0;
	# solve the quadratic equation, if it's not solvable then we don't have a point
	next unless Crypt::OpenSSL::EC::EC_POINT::set_compressed_coordinates_GFp($context->{group}, $pwe, $candidate, $is_odd, $context->{bnctx});

	# If there's a solution to the equation then the point must be
	# on the curve so why check again explicitly? OpenSSL code
	# says this is required by X9.62. We're not X9.62 but it can't
	# hurt just to be sure.
	next unless Crypt::OpenSSL::EC::EC_POINT::is_on_curve($context->{group}, $pwe, $context->{bnctx});
	if ($context->{cofactor}->cmp(Crypt::OpenSSL::Bignum->one()))
	{
	    # make sure the point is not in a small sub-group
	    next unless Crypt::OpenSSL::EC::EC_POINT::mul($context->{group}, $pwe, \0, $pwe, $context->{cofactor}, $context->{bnctx});
	    next if Crypt::OpenSSL::EC::EC_POINT::is_at_infinity($context->{group}, $pwe);
	}

	# This is the new generator
	last;
    }
    return $pwe;
}

#####################################################################
sub eap_pwd_fail
{
    my ($self, $context, $p, $reason) = @_;

    $self->eap_failure($p->{rp}, $context);
    $context->{state} = 'FAILURE';
    return ($main::REJECT, $reason);
}

#####################################################################
# Prepend octets on the left to make $s $l bytes long
sub pad_on_left
{
    my ($s, $l) = @_;

    return pack('x') x ($l - length($s)) . $s;
}

#####################################################################
# Convert a Bignum to bin and pad on left to length l
sub bn_to_bin_pad
{
    my ($b, $l) = @_;

    return pad_on_left($b->to_bin, $l);
}

#####################################################################
# Convert an element into x and y in binary format padded on the left
sub element_to_x_y_bin
{
    my ($context, $element) = @_;

    my $x = Crypt::OpenSSL::Bignum->new();
    my $y = Crypt::OpenSSL::Bignum->new();
    Crypt::OpenSSL::EC::EC_POINT::get_affine_coordinates_GFp($context->{group}, $element, $x, $y, $context->{bnctx});
    
    # Make sure we got some results from the foregoing
    return unless $x && $y;

    # May need to pad them on the left to be the same length as p
    my $x_bin = bn_to_bin_pad($x, $context->{primelen});
    my $y_bin = bn_to_bin_pad($y, $context->{primelen});

    return ($x_bin, $y_bin);
}

#####################################################################
# Generate ks or kp
# ks = ((pwe^Scalar_P mod p) * Element_P)^s_rand mod p
# kp = ((pwe^Scalar_S mod p) * Element_S)^p_rand mod p
sub generate_k
{
    my ($self, $context, $scalar, $element, $rand) = @_;

    my $K = Crypt::OpenSSL::EC::EC_POINT::new($context->{group});
    Crypt::OpenSSL::EC::EC_POINT::mul($context->{group}, $K, \0, $context->{pwe}, $scalar, $context->{bnctx});
    Crypt::OpenSSL::EC::EC_POINT::add($context->{group}, $K, $K, $element, $context->{bnctx});
    Crypt::OpenSSL::EC::EC_POINT::mul($context->{group}, $K, \0, $K, $rand, $context->{bnctx});

    if (!$K)
    {
	$self->log($main::LOG_ERR, 'EAP-PWD error computing shared key');
	return;
    }

    # ensure that the shared key isn't in a small sub-group
    if (   $context->{cofactor}->cmp(Crypt::OpenSSL::Bignum->one())
	&& !Crypt::OpenSSL::EC::EC_POINT::mul($context->{group}, $K, \0, $K, $context->{cofactor}, $context->{bnctx}))
    {
	$self->log($main::LOG_ERR, 'EAP-PWD cannot multiply shared key point by order');
	return;
    }

    if (Crypt::OpenSSL::EC::EC_POINT::is_at_infinity($context->{group}, $K))
    {
	$self->log($main::LOG_ERR, 'EAP-PWD shared key point is at infinity');
	return;
    }

    my $k = Crypt::OpenSSL::Bignum->new();
    Crypt::OpenSSL::EC::EC_POINT::get_affine_coordinates_GFp($context->{group}, $K, $k, \0, $context->{bnctx});
    return $k;
}

#####################################################################
# Generate a confirm value given ks
# This is used to generate our confirm_s and the verify confirm_p
# Confirm_S = H(ks | Element_S | Scalar_S | Element_P | Scalar_P | Ciphersuite)
# Confirm_P = H(kp | Element_P | Scalar_P | Element_S | Scalar_S | Ciphersuite)
sub generate_confirm
{
    my ($self, $context, $ks, $element_s, $scalar_s, $element_p, $scalar_p) = @_;

    my ($s_x_bin, $s_y_bin) = element_to_x_y_bin($context, $element_s);
    my ($p_x_bin, $p_y_bin) = element_to_x_y_bin($context, $element_p);

    my $ks_bin = bn_to_bin_pad($ks, $context->{primelen});
    my $scalar_s_bin = bn_to_bin_pad($scalar_s, $context->{primelen});
    my $scalar_p_bin = bn_to_bin_pad($scalar_p, $context->{primelen});
    my $confirm = H($ks_bin . $s_x_bin . $s_y_bin . $scalar_s_bin . $p_x_bin . $p_y_bin .  $scalar_p_bin . $context->{ciphersuite});

    return $confirm;
}


#####################################################################
# Called by EAP.pm when an EAP Response (other than Identity)
# is received
sub response
{
    my ($classname, $self, $context, $p, $type, $typedata) = @_;

    if (!length($typedata))
    {
	# This is a fragment ACK from the supplicant, send the next fragment
	eap_pwd_send_pending($self, $context, $p);
    }

    my ($flags) = unpack('C', $typedata);
    my ($length, $data);
    if ($flags & $Radius::EAP_52::L_bit)
    {
	($flags, $length, $data) = unpack('C n a*', $typedata);
	return ($main::IGNORE, 'EAP-PWD invalid length in first fragment')
	    if $length < (length($typedata)+5);
    }
    else
    {
	($flags, $data) = unpack('C a*', $typedata);
    }
    $context->{recv_buffer} .= $data;
    if ($flags & $Radius::EAP_52::M_bit)
    {
	# This is a fragment from the supplicant (but not the last). Accumulate it
	# acknowledge it and wait for more data
	# EAP-PWD ACK:
	$self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_PWD);
	return ($main::CHALLENGE, 'EAP-PWD Challenge (fragment ACK)');
    }
    my $opcode = $flags & $Radius::EAP_52::PWD_EXCH_MASK;

    # $context->{recv_buffer} now has our message


    # Respond depending on what state we are in
    if ($context->{state} eq 'PWD_ID_Response' && $opcode == $Radius::EAP_52::PWD_EXCH_ID)
    {
	$self->log($main::LOG_DEBUG, "EAP-PWD PWD_ID_Response");
	# Expect EAP-pwd-ID/Response
        #   Ciphersuite, Token, Password Processing Method, Peer_ID
	my ($group_num, $random_function, $prf, $token, $prep, $identity) 
	    = unpack('n C C a4 C a*', $context->{recv_buffer});
	$context->{recv_buffer} = undef;

	# Check the token
	return eap_pwd_fail($self, $context, $p, "Incorrect EAP-PWD token")
	    unless $token eq $context->{token};

	# Check that the random_function, prf and prep methods are acceptable
	return eap_pwd_fail($self, $context, $p, "EAP-PWD peer requires unsupported random function: $random_function")
	    unless $random_function == $Radius::EAP_52::PREF_RANDOM_RFC5931;
	return eap_pwd_fail($self, $context, $p, "EAP-PWD peer requires unsupported PRF: $prf")
	    unless $prf == $Radius::EAP_52::PRF_HMAC_SHA256;
	return eap_pwd_fail($self, $context, $p, "EAP-PWD peer requires unsupported prep method: $prep")
	    unless $prep == $Radius::EAP_52::PREP_NONE;

	$context->{group_num} = $group_num;
	$context->{random_function} = $random_function;
	$context->{prf} = $prf;
	$context->{ciphersuite} = pack('n c c', $context->{group_num}, $context->{random_function}, $context->{prf});

	# Check that the peers group selection is OK:
	my $nid = group_description_to_NID($group_num);
	return eap_pwd_fail($self, $context, $p, "Unsupported EAP-PWD group description number $group_num")
	    unless defined $nid;
	

	# Need the correct plaintext password
	my $lookup_identity = $identity;
	$lookup_identity =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};

	my ($user, $result, $reason) = $self->get_user($lookup_identity, $p);
	if (!$user || $result != $main::ACCEPT)
	{
	    $self->eap_failure($p->{rp}, $context);
	    return ($main::REJECT, "EAP-PWD failed: no such user $lookup_identity");
	}
	my $password = $self->get_plaintext_password($user);
	$password = prep_password($self, $password, $prep);
	return eap_pwd_fail($self, $context, $p, "EAP-PWD could not prep password")
	    unless defined $password;

	$context->{group} = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name($nid);
	return ($main::IGNORE, "EAP-PWD could not create group for NID $nid") 
	    unless $context->{group};

	$context->{prime} = Crypt::OpenSSL::Bignum->new();
	$context->{bnctx} = Crypt::OpenSSL::Bignum::CTX->new();
	$context->{group}->get_curve_GFp($context->{prime}, \0, \0, $context->{bnctx});
	$context->{primelen} = $context->{prime}->num_bytes();
	$context->{order} = Crypt::OpenSSL::Bignum->new();
	$context->{group}->get_order($context->{order}, $context->{bnctx});
	$context->{cofactor} = Crypt::OpenSSL::Bignum->new();
	$context->{group}->get_cofactor($context->{cofactor}, $context->{bnctx});
	$context->{s_rand} = Crypt::OpenSSL::Bignum->new();
	$context->{mask} = Crypt::OpenSSL::Bignum->new();

	# - choose two random numbers, 1 < s_rand, s_mask < r
	# - compute Scalar_S = (s_rand + s_mask) mod r
	# - compute Element_S = inv(s_mask * PWE)
	$context->{s_rand}->rand_range($context->{order});
	$context->{mask}->rand_range($context->{order});
	# Scalar_S:= (s_rand + s_mask) mod r
	$context->{scalar_s} = $context->{s_rand}->add($context->{mask});
	$context->{scalar_s} = $context->{scalar_s}->mod($context->{order}, $context->{bnctx});

	# Compute the PWE based on the users correct password and the preprocessing algorithm
	$context->{pwe} = compute_pwe($self, $context, $group_num, $password, $main::hostname, $identity, $token);
	return eap_pwd_fail($self, $context, $p, 'EAP-PWD Could not generate PWE')
	    unless $context->{pwe};

	# Compute Element_S = inv(s_mask * PWE)
	$context->{element_s} = Crypt::OpenSSL::EC::EC_POINT::new($context->{group});
	Crypt::OpenSSL::EC::EC_POINT::mul($context->{group}, $context->{element_s}, \0, $context->{pwe}, $context->{mask}, $context->{bnctx});
	Crypt::OpenSSL::EC::EC_POINT::invert($context->{group}, $context->{element_s}, $context->{bnctx});

	# Send EAP-pwd-Commit/Request
        #   Scalar_S, Element_S
	# new state PWD_Commit_Response

	# 3.2.2. EAP-pwd-Commit
	# Element (as x, y) followed by Scalar
	# x, y generated per section 3.3.2. Elements in ECC Groups
	# They are transmitted in binary form padded on the left
	my ($x_bin, $y_bin) = element_to_x_y_bin($context, $context->{element_s});

	# Make sure we got some results from the foregoing
	return eap_pwd_fail($self, $context, $p, 'EAP-PWD generation failure')
	    unless $x_bin && $y_bin && $context->{scalar_s};

	my $length_of_order = $context->{order}->num_bytes();
	my $scalar_s_bin = bn_to_bin_pad($context->{scalar_s}, $length_of_order);

	my $commit = $x_bin . $y_bin . $scalar_s_bin;

	$context->{state} = 'PWD_Commit_Response';
	return eap_pwd_send($self, $context, $p, $Radius::EAP_52::PWD_EXCH_COMMIT, $commit);
    }
    elsif ($context->{state} eq 'PWD_Commit_Response' && $opcode == $Radius::EAP_52::PWD_EXCH_COMMIT)
    {
	$self->log($main::LOG_DEBUG, "EAP-PWD PWD_Commit_Response");
	# Expect EAP-pwd-Commit/Response
        #   Scalar_P, Element_P

	my ($x_bin, $y_bin, $scalar_p_bin) = unpack("a$context->{primelen} a$context->{primelen} a*", $context->{recv_buffer});
	$context->{recv_buffer} = undef;

	return eap_pwd_fail($self, $context, $p, 'EAP-PWD bad data in P-pwd-Commit/Response')
	    unless length($scalar_p_bin) == $context->{order}->num_bytes();

	$context->{element_p} = Crypt::OpenSSL::EC::EC_POINT::new($context->{group});
	$context->{scalar_p} = Crypt::OpenSSL::Bignum->new_from_bin($scalar_p_bin);
	my $x = Crypt::OpenSSL::Bignum->new_from_bin($x_bin);
	my $y = Crypt::OpenSSL::Bignum->new_from_bin($y_bin);

	Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp($context->{group}, $context->{element_p}, $x, $y, $context->{bnctx});

	# Check for reflection attack per 2.8.5.2. EAP-pwd-Commit Exchange
	return eap_pwd_fail($self, $context, $p, 'EAP-PWD reflection attack detected')
	    if (   $context->{scalar_p} eq $context->{scalar_s}
		&& Crypt::OpenSSL::EC::EC_POINT::cmp($context->{group}, $context->{element_p}, $context->{element_s}, $context->{bnctx}) == 0);


	# - compute KS = (s_rand * (Scalar_P * PWE + Element_P))
	# - compute ks = F(KS)
	# - compute Confirm_S = H(ks | Element_S | Scalar_S | Element_P | Scalar_P | Ciphersuite)
	$context->{ks} = generate_k($self, $context, $context->{scalar_p}, $context->{element_p}, $context->{s_rand});
	return eap_pwd_fail($self, $context, $p, 'EAP-PWD cold not generate ks')
	    unless $context->{ks};

	# Now compute confirm_s
	$context->{confirm_s} = generate_confirm($self, $context, $context->{ks}, $context->{element_s}, $context->{scalar_s}, $context->{element_p}, $context->{scalar_p});
	return eap_pwd_fail($self, $context, $p, 'EAP-PWD cold not generate confirm_s')
	    unless $context->{confirm_s};

	# Send EAP-pwd-Confirm/Request
	#   Confirm_S
	# new state PWD_Confirm_Response
	$context->{state} = 'PWD_Confirm_Response';
	return eap_pwd_send($self, $context, $p, $Radius::EAP_52::PWD_EXCH_CONFIRM, $context->{confirm_s});
    }
    elsif ($context->{state} eq 'PWD_Confirm_Response' && $opcode == $Radius::EAP_52::PWD_EXCH_CONFIRM)
    {
	$self->log($main::LOG_DEBUG, "EAP-PWD PWD_Confirm_Response");
	# Expect EAP-pwd-Confirm/Response
	#   Confirm_P
	my $confirm_p = $context->{recv_buffer};
	$context->{recv_buffer} = undef;

	return eap_pwd_fail($self, $context, $p, "EAP-PWD incorrect confirm_p length")
	    unless length($confirm_p) == 32; # Valid for the H random function only

	# Verify confirm_p
	my $expected_confirm_p = generate_confirm($self, $context, $context->{ks}, $context->{element_p}, $context->{scalar_p}, $context->{element_s}, $context->{scalar_s}); 
	return eap_pwd_fail($self, $context, $p, "EAP-PWD confirm_p verify failed")
	    unless $confirm_p eq $expected_confirm_p ;

	# MK = H(ks | Confirm_P | Confirm_S)
	# Pad ks on the left to BN_num_bytes(grp->prime)
	my $ks_bin = bn_to_bin_pad($context->{ks}, $context->{primelen});
	my $MK = H($ks_bin . $confirm_p . $context->{confirm_s});
	# At last, the master key!

	# Now need MSK and EMSK per 2.9. Management of EAP-pwd Keys
	my $scalar_p_bin = bn_to_bin_pad($context->{scalar_p}, $context->{primelen});
	my $scalar_s_bin = bn_to_bin_pad($context->{scalar_s}, $context->{primelen});
	my $method_id = H($context->{ciphersuite} . $scalar_p_bin . $scalar_s_bin);
	my $type_code = pack('C', $Radius::EAP::EAP_TYPE_PWD);
	my $session_id = $type_code . $method_id;
	my ($msk, $emsk) = unpack('a64 a64', KDF($MK, $session_id, 1024));

	$p->{rp}->{msk} = $msk;
	$p->{rp}->{emsk} = $emsk;
	# REVISIT: key caching?
	if ($self->{AutoMPPEKeys})
	{
	    my ($send, $recv) = unpack('a32 a32', $msk);
	    # Note these are swapped because its for the AP end of the encryption
	    $p->{rp}->change_attr('MS-MPPE-Send-Key', $recv);
	    $p->{rp}->change_attr('MS-MPPE-Recv-Key', $send);
	}

	# Send EAP-Success  
	#  new state SUCCESS
	$self->eap_success($p->{rp}, $context);
	$context->{state} = 'SUCCESS';
	return ($main::ACCEPT); # Success, all done
    }
    else
    {
	$context->{recv_buffer} = undef;
	return ($main::IGNORE, 'Unexpected EAP-PWD message');
    }
}

#####################################################################
# Start the sending of a new EAP-PWD message back to the supplicant
sub eap_pwd_send
{
    my ($self, $context, $p, $opcode, $data) = @_;

    $context->{opcode} = $opcode;
    $context->{send_buffer} = $data;
    $context->{first_frag} = 1;
    return eap_pwd_send_pending($self, $context, $p); # Send the first fragment
}

#####################################################################
# Send any pending bytes to be sent back to the NAS
# CAUTION: Fragmentation is not well tested, since wpa_supplicant does not yet support it
# and length is not yet sent
sub eap_pwd_send_pending
{
    my ($self, $context, $p) = @_;

    my $maxfrag = 1020; # Required by RFC 5931
    my $framedmtu = $p->get_attr('Framed-MTU'); 
    $maxfrag = $framedmtu if defined $framedmtu && $framedmtu < $maxfrag;

    my $length = length($context->{send_buffer});
    my $data = substr($context->{send_buffer}, 0, $maxfrag, '');

    # Bogus ACK?
    return ($main::IGNORE, 'EAP-PWD No more data to send!')
	unless length($data);

    my $flags = $context->{opcode};
    $flags |= $Radius::EAP_52::M_bit if length($context->{send_buffer});

    my $message;
    if ($context->{first_frag} && 0)  # wpa_supplicant does not support length or fragmentation yet
    {
	$flags |= $Radius::EAP_52::L_bit;
	$message = pack('C n a*', $flags, $length, $data);
    }
    else
    {
	$message = pack('C a*', $flags, $data);
    }

    $context->{first_frag} = 0;
    $self->eap_request($p->{rp}, $context, $Radius::EAP::EAP_TYPE_PWD, $message);
    return ($main::CHALLENGE, 'EAP-PWD Challenge');
}

1;
