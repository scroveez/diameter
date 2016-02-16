# AuthDBUNIX.pm
#
# Object for handling Authentication DBM password files
# Digital UNIX on an Alpha automatically maintains a NDBM database that
# tracks the /etc/passwd file.  
# 
# Here is an Auth module that will use it.  Should be about as fast as
# the AuthUNIX module w/cache, however will instantly respond to 
# changed
# user info.  Does not support the "useringroup" method.
# When this is done, it will probably be moved into the core 
# distribution and documented.
#
# Author: Aaron Nabil <nabil@spiritone.com>
# This module was contributed by a Radiator user, and is 
# offered as-is, untested and unsupported.

package Radius::AuthDBUNIX;
@ISA = qw(Radius::AuthFILE);
use Radius::AuthFILE;
use Radius::User;
use Fcntl;
use NDBM_File;
use strict;
use vars qw($VERSION @ISA);

sub initialize 
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Filename} = '%D/passwd';
}

sub findUser 
{
    my ($self, $name) = @_;

    my $user;
    my $type = ref($self);
    my $filename = &main::format_special($self->{Filename});

    my %passwdDB;
    tie(%passwdDB, 'NDBM_File', $filename, O_RDONLY, 0) 
	|| &main::log($main::LOG_WARNING,
		      "Could not open user database file '$filename' in $type: $!");

    my $value = $passwdDB{$name};

    if ($value =~ /^([^\0]*)\0([^\0]*)\0(........).....([^\0]*)\0([^\0]*)\0([^\0]*)\0/s 
	&& $1 eq $name) 
    {
        my ($name, $passwd, $uid, $gid, $gcos, $home, $shell);
	$user = new Radius::User $name;

	$name = $1;
	$passwd = $2;
	($uid, $gid) = unpack "I I",$3;
	$gcos = $4;
	$home = $5;
	$shell = $6;

        $user->get_check->add_attr('Encrypted-Password', $passwd);
    } 
    else 
    {
        undef $user;
    }

    untie %passwdDB;
    return $user;
}

1;
