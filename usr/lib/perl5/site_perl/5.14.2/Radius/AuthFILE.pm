# AuthFILE.pm
#
# Object for handling Authentication from flat files
# AuthGeneric::handle_request is not overridden, only the routine to
# find a user record (findUser).
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: AuthFILE.pm,v 1.42 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthFILE;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Radius::User;
use strict;

%Radius::AuthFILE::ConfigKeywords = 
('Filename'        => 
 ['string', 'Specifies the filename that holds the user database. Defaults to %D/users, i.e. a file named users in DbDir. The file name can include special formatting characters ', 0],

 'Nocache'         => 
 ['flag', 'Disables caching of the user database, and forces Filename to be reread for every Authentication. If not set, AuthBy FILE will only reread the user database when the files modification time changes. Don\'t use this parameter unless you have to, because it can be very slow for any more than 1000 users or so. If you need think you need Nocache, you should consider DBFILE instead.', 1],
);


# RCS version number of this module
$Radius::AuthFILE::VERSION = '$Revision: 1.42 $';

#####################################################################
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();

    # Prime the cache
    $self->findUser unless $self->{Nocache};
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{Filename} = '%D/users';
}

#####################################################################
# Finds the named user by looking in a flat file user database
# Reads same format files as Merit radius, RadiusNT and others
# If Nocache is set, it always reads the file from scratch
# Otherwise it will reread the file whenever its mod time changes
# Each user entry is stored as an array of 2 strings [checkitem, replyitems]
# They will be parsed when a user entry is actually found
sub findUser
{
    my ($self, $look_for, $p) = @_;

    # Trying to prime the cache, don't. Do it on first request.
    return undef if(!defined($look_for));

    # Use the filename as a key to the cache structure.
    my $type = ref($self);
    my $filename = &Radius::Util::format_special($self->{Filename}, $p);

    if ($self->{Nocache} || $self->fileHasChanged($filename))
    {
	# Clear the cache
	%{$self->{Users}{$filename}} = ();

	$self->log($main::LOG_DEBUG, "Reading users file $filename", $p);
	if (!open(FILE, $filename))
	{
	    $self->{LastModTime}{$filename} = 0; # Make sure we read it later
	    $self->log($main::LOG_ERR, 
		       "Could not open user database file $filename in $type: $!", $p);
	    return (undef, 1);
	}

	my $default_number = '';
	my $pushbackline;
	while ($_ = $pushbackline || <FILE>)
	{
	    $pushbackline = '';
	    chomp;
	    
	    # Skip comment lines and blank lines
	    next if /^#/ || /^\s*$/;
	    
	    if (/^"([^"]+)"\s*(.*)/ || /^(\S+)\s*(.*)/)
	    {
		# Start of a new record. The user name
		# is the first field. Double quoted usernames with whitespace are permitted
		my ($username, $check) = ($1, $2);
		
		# Make a unique name for each 'DEFAULT' entry
		# The first one is just DEFAULT, the following ones
		# are DEFAULT1, DEFAULT2 etc.
		if ($username eq 'DEFAULT')
		{
		    $username = "DEFAULT$default_number";
		    $default_number++;
		}
		
		# Not the one we want
		next if $self->{Nocache} && $look_for ne $username;

		my ($reply, $gotallchecks);
		$gotallchecks++ if $check !~ /,\s*$/; # End of check items?

		# Now get all the rest of the lines for this user
		# until we see the start of a new user or EOF
		while (<FILE>)
		{
		    chomp;
		    # Skip comment lines and blank lines
		    next if /^#/ || /^\s*$/;

		    if (/^(\S+)\s*(.*)/)
		    {
			# Start of a new record, push this line back
			# for the outer loop to read
			$pushbackline = $_;
			last;
		    }

		    if ($gotallchecks)
		    {
			# This must be a reply item(s)
			$reply .= $_;
		    }
		    else
		    {
			# This must be a check item(s)
			$check .= $_;
			# Last check item if no comma at end
			$gotallchecks++ if $_ !~ /,\s*$/;
		    }
		}

		# Each entry stored as 2 strings, parsed later
		$self->{Users}{$filename}{$username} = [$check, $reply];

		# Got the whole user record, return the user 
		# we found last
		# if looking for a particular one
		last if $self->{Nocache};
		
	    }
	}
	close(FILE)
	    || $self->log($main::LOG_ERR, 
		      "Could not close user database file $filename in $type: $!", $p);
    }

    # This is the check, reply array we are interested in
    my $found = $self->{Users}{$filename}{$look_for};
    return $found ? Radius::User->new($look_for, $$found[0], $$found[1]) 
	: undef;
}

1;

