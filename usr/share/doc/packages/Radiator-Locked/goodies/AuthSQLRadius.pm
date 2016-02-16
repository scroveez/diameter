# AuthSQLRADIUS.pm
#
# Object for handling Authentication from remote radius servers
# based on SQL lookup.
#
# OBSOLETE: see the new AuthBy SQLRADIUS in the standard package
#
# Author: Stephen Roderick (steve@uspops.com)

package Radius::AuthSQLRADIUS;
@ISA = qw(Radius::AuthRADIUS Radius::SqlDb);
use Radius::AuthRADIUS;
use Radius::Radius;
use Radius::Select;
use Radius::SqlDb;
use Socket;
use Fcntl;
use strict;
use vars qw($VERSION @ISA);

%Radius::AuthSQLRADIUS::ConfigKeywords = 
    (
     'HostSelect' => 'string',
     );


#####################################################################
sub activate
{
    my ($self) = @_;

    # The following entries will stop the AuthRADIUS class from failing
    $self->{Host} = [];
    $self->{Secret} = '';
}

#####################################################################
# Do per-instance default initialization
sub initialize
{
    my ($self) = @_;

    $self->Radius::AuthRADIUS::initialize;
    $self->Radius::SqlDb::initialize;

    $self->{HostSelect} = 'select HOSTS,SECRET from PROXYHOSTS where DNIS=\'%{Called-Station-Id}\'';

}

#####################################################################
# Handle a request
sub handle_request
{
    my ($self, $p, $rp, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, "Handling with Radius::AuthSQLRADIUS");

    # Remove any previous hosts
    $self->{Host} = [];
    $self->{Secret} = '';

    # Do not Forward if HostSelect is not defined or is empty
    if (!defined $self->{HostSelect} || ($self->{HostSelect} eq ''))
    {
        &Radius::Log::log($main::LOG_DEBUG,
                 "No HostSelect statement defined, request not forwarded to AuthRADIUS");
        return ($main::IGNORE); # No reply
    }
    
    if ($self->loadHosts($p))
    {
    	return $self->SUPER::handle_request($p, $rp, $extra_checks);
    }
    
    &Radius::Log::log($main::LOG_DEBUG,
		      "HostSelect statement returned no results");
    return ($main::IGNORE); # No reply
}

#####################################################################
# Load all of the hosts from the database
sub loadHosts
{
    my ($self, $p) = @_;
    
    my $select = &Radius::Util::format_special($self->{HostSelect},$p);
    
    # We need to do the initial query
    my $sth = $self->prepareAndExecute($select);
    
    my $rowCount = 0;
    
    if (defined $sth)
    {
	my @row;
	
    	while(@row = $self->getOneRow($sth))
	{
	    &Radius::Log::log($main::LOG_DEBUG, "Adding Host $row[0]");
	    
	    if ($rowCount == 0)
	    {
		$self->{Secret} = $row[1]	if defined $row[1];
		$self->{AuthPort} = $row[2]	if defined $row[2];
		$self->{AcctPort} = $row[3]	if defined $row[3];
		$self->newReplyItems($row[4])	if defined $row[4];
		&Radius::Log::log($main::LOG_DEBUG, "Using AuthPort $row[2] and AcctPort $row[3]");
	    }
	    $self->addHost($row[0]);
	    $rowCount++;
    	}
	$sth->finish();
    }
    return $rowCount;
}

sub newReplyItems
{
    my($self, $items) = @_;
    
    if (defined $self->{AddToReply} && length($self->{AddToReply}))
    {
	$self->{AddToReply} .= ',';
    }
    $self->{AddToReply} .= $items;
}

1;

