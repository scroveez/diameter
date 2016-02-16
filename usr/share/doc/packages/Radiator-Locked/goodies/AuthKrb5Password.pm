# AuthKrb5Password.pm
#
# Object for handling Kerberos 5 password verification (an interim 
# measure on behalf of clients that can't yet authenticate using the 
# Kerberos protocol).
# Pre-requisites: Authen-Krb5Password module from CPAN.
# Written by: Shumon Huque <shuque -at- isc.upenn.edu>
#

package Radius::AuthKrb5Password;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Authen::Krb5Password;
use strict;
use vars qw($VERSION @ISA);

%Radius::AuthKrb5Password::ConfigKeywords =
    ('Service' => 'string',
     'Keytab' => 'string',
     );

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my($self) = @_;

    $self->SUPER::initialize;
    $self->{Service} = 'radius';
    $self->{Keytab} = '';
    $self->{NoDefault} = 1; # never look for DEFAULT Kerberos principal
    $self->{Fork} = 1; # always fork since we could block if a KDC is down
}

#####################################################################
# We subclass this to do nothing: there are no check items
# except the password, and only if its not an EAP
sub checkUserAttributes
{
    my ($self, $user, $p) = @_;
    
    # Short circuit authentication in EAP requests ?
    return ($main::ACCEPT) 
	if $p->getAttrByNum($Radius::Radius::MESSAGE_AUTHENTICATOR);

    return $self->check_plain_password($p->getUserName(), $p->decodedPassword(), undef, $p);
}

#####################################################################
# check_plain_password()
# $decodedpw is the password being authenticated
# $correctpw is the correct password if known (N/A for this module)
# $name is the user name to be authenticated
# Attempts to authenticate the user via Kerberos 5
sub check_plain_password
{
    my ($self, $name, $decodedpw, $correctpw, $p, $encrypted) = @_;

    $name =~ s/@[^@]*$//;
    my ($result, $reason);

    my $rc = kpass($name, $decodedpw, $self->{Service}, '', $self->{Keytab});
    if ($rc == 1) {
	$result = $main::ACCEPT;
    } elsif ($rc == 0) {
	$result = $main::REJECT;
	$reason = "Authentication failure";
    } else {
	# An error occurred.
	$result = $main::REJECT;
	$reason = "Kerberos error";
    }
    return($result, $reason);
}

#####################################################################
# Skeletal findUser function.
sub findUser
{
    my($self, $name, $p) = @_;
    return Radius::User->new();
}

1;
