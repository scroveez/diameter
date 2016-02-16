# rsaam_multi_hook.pl
#
# Hook for rsaam_multi.cfg
# Categorizes requests according to whether they should be sent
# to RSAAM OnDemand or RSAAM SecuriID authentication
#
# Copyright (C) Open System Consultants
# Author: Mike McCauley (mikem@open.com.au)
# $Id: rsaam_multi_hook.pl,v 1.1 2009/09/01 06:19:14 mikem Exp $

sub {
    my $p = ${$_[0]};
    # If there is already a State, we use that to figure out where to go

    my $state = $p->get_attr('State');
    if (defined $state)
    {
	# Have State, been throught a target clause already
	# If the state has been tagged with OSCTARGET, it is part of an ongoing conversation
	# remove it from the State and use the value
	if ($state =~ /^OSCTARGET=(.*);(.*)/)
	{
	    $p->change_attr('State', $2);
	    $p->add_attr('OSCTargetDirector', $1);
	}
	# Else do not change the State: must be being used by something else
    }
    else
    {
	# No state, use the password to figure out where to send it
	my $password = $p->decodedPassword();
	if (length($password) <= 4)
	{
	    # Assume its a bare PIN and therfore the first request in an OnDemand conversation
	    $p->add_attr('OSCTargetDirector', 'OnDemand');
	}
	else
	{
	    # Assume its the start of a SecurID conversation
	    $p->add_attr('OSCTargetDirector', 'SecurID');
	}
    }
}

