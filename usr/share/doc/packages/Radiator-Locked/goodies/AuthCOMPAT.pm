# AuthCOMPAT.pm
#
# Object for handling exact Livingston compatibility.
# This module was contributed by a Radiator user and is offered
# almost exactly it was contributed. It provides "exact"
# Livingston user file conpatibility, especially in the area
# of Password="UNIX"
#
# We have not tested, verified or documented it. It is 
# offered as-is and unsupported.
#
# Author: Aaron Nabil (nabil@spiritone.com)
# Cleaned up and reformatted by Mike McCauley
# $Id: AuthCOMPAT.pm,v 1.2 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthCOMPAT;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use strict;
use vars qw($VERSION @ISA);

sub keyword 
{
    my ($self, $file, $keyword, $value) = @_;

    if ($keyword eq 'CascadeTo') 
    {
	$self->{CascadeTo} = $value;
	return 1;
    } 
    return $self->SUPER::keyword($file, $keyword, $value);
}

sub findUser 
{
    my ($self, $name) = @_;

    my $fileuser;
    my $unixuser;
    my $replyuser = new Radius::User $name;
    
    $fileuser = $self->{AuthFILE}->findUser($name);
    
    if ($fileuser) 
    {
        my $fPass;
        if ($fPass = $fileuser->get_check->get_attr('Password')) 
	{
	    my $i;
	    my ($name, $value);
	    
	    $i = 0;
	    while (($name, $value) = $fileuser->get_reply->get_attr_val_n($i++)) {
		$replyuser->get_reply->add_attr($name, $value);
	    }
	    
	    $i = 0;
	    while (($name, $value) = $fileuser->get_check->get_attr_val_n($i++)) {
		$replyuser->get_check->add_attr($name, $value);
	    }

            if ($fPass eq 'UNIX') 
	    {
		if ($name =~ /^DEFAULT/) 
		{
	            &main::log($main::LOG_DEBUG, "$name: default entry");
                    $replyuser->get_check->delete_attr('Password');
                    $replyuser->get_check->change_attr('Auth-Type', $self->{CascadeTo});
		} 
		else 
		{
		    # we don't want them to be able to log in with "UNIX" if
		    # the passwd lookup fails.
                    $replyuser->get_check->change_attr('Password', 'NotAGuessableString');
                    $unixuser = $self->{AuthUNIX}->findUser($name);
                    if ($unixuser) {
                        my $uPass;
                        if ($uPass = $unixuser->get_check->get_attr('Encrypted-Password')) 
			{
                            $replyuser->get_check->delete_attr('Password');
                            $replyuser->get_check->change_attr('Encrypted-Password', $uPass);
	                }
                    }
	        }
		return $replyuser;
	    }
	}
    }
    
    return $fileuser;
}

sub object 
{
    my ($self, $file, $keyword, $args) = @_;

    if ($keyword eq 'FileAuthBy') 
    {
	my $filename = "Radius/Auth$args.pm";
	if (eval("require \"$filename\""))
	{
	    my $class = "Radius::Auth$args";
	    my $handler = $class->new($file, $args);
	    $self->{AuthFILE}=$handler;
	} else 
	{
	    &main::log($main::LOG_ERR, "AuthCOMPAT could not load FileAuthBy authentication module $filename: $@");
	}
    } 
    elsif ($keyword eq 'UnixAuthBy') 
    {
	my $filename = "Radius/Auth$args.pm";
	if (eval("require \"$filename\"")) 
	{
	    my $class = "Radius::Auth$args";
	    my $handler = $class->new($file, $args);
	    $self->{AuthUNIX}=$handler;
	} 
	else 
	{
	    &main::log($main::LOG_ERR, "AuthCOMPAT could not load UnixAuthBy authentication module $filename: $@");
	}
    } 
    else 
    {
	return 0;
    }
    return 1;
}

1;
