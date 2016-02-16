# lookupauthgroup.pl
#
# This hook runs after an LDAP user authentication search.
# Its job is to implement the business logic required by <yourcompany> for 
# controlling access to devices and systems based on user groups 
# and device groups.
# It does this by looking up the usergroup,devicegroup 
# in the SQL GROUPAUTH table,
# and adds the check and reply items found to the current user record.
# The user group is determined from an LDAP lookup
# Author: Mike McCauley.
use strict;

# You will need something like this your the AuthLDAP
#            # This is the gorup search filter, it wil be passed the CN of the user
#            GroupSearchFilter (uniquemember=%1)
#            #This is the basedn for the group search
#            GroupBaseDN cn=Groups,dc=yourcompany,dc=com

# $self points to the AuthBy LDAP clause executing this hook
# $username is the base User-Name
# $p is the current incoming request
# $user is the Radius::User object currently being constructed
# $entry is a Net::LDAP entry for the current record
# $rp is the reply packet currently being constructed
sub
{
    my ($self, $username, $p, $user, $entry, $rp) = @_;

    # Find an SQL clause that we can use to access the database
    my $sqlclause = Radius::AuthGeneric::find('SqlAuth');
    return unless $sqlclause;

    # Get the user name after any possible rewrites
    my $username = $p->getUserName();
    my $userdn = $entry->dn;

    # Get the user groups this user is in
    # This will run the equivalent of
    # ldapsearch -D ..... -s sub -b 'cn=Groups,dc=yourcompany,dc=com' -x '(uniquemember=cn=someusername,ou=someou,cn=users,dc=yourcompany,dc=com)' cn
    my @usergroups = $self->getUserGroups($userdn, $p);

    # If there was not at least one user group, reject
    if (!@usergroups)
    {
	$sqlclause->log($main::LOG_WARNING, "$username ($userdn) is not a member of at least one user group. Rejecting");
	$user->get_check->add_attr('Auth-Type', 'Reject:Not a member of at least one user group');
	return;
    }

    # Get the device group name from the OSC-Client-Identifier
    my $devicegroup = $p->get_attr('OSC-Client-Identifier');
    # If there is not one, bail out
    if (!defined $devicegroup)
    {
	$sqlclause->log($main::LOG_ERR, "No OSC-Client-Identifier found in request. Rejecting");
	$user->get_check->add_attr('Auth-Type', 'Reject:No OSC-Client-Identifier found in request');
	return;
    }

    my $hits;
    # Performance note: there might be an opportunity to use
    # where (USERGROUP=? or USERGROUP=? or .....)
    # so as to do one SQL query instead of one for each usergroup,
    # but its unclear how the priority would be resolved.
    # Caution: if the user is in multiple groups, all of which have
    # access to the devicegroup, the order of check and reply items 
    # is not defined.
    foreach my $usergroup (@usergroups)
    {
	my $q = 'select TYPE, ATTRIBUTE, VALUE from GROUPAUTH where USERGROUP=? and DEVICEGROUP=? order by PRIORITY desc';

	my $sth = $sqlclause->prepareAndExecute($q, $usergroup, $devicegroup);
	if ($sth)
	{
	    my ($type, $attribute, $value);
	    while (($type, $attribute, $value) = $sth->fetchrow())
	    {
		$hits++;
		if ($type == 0)
		{
		    # This is a check item
		    $user->get_check->add_attr($attribute, $value);
		}
		else
		{
		    # This is a reply item
		    $user->get_reply->add_attr($attribute, $value);
		}
	    }
	    $sth->finish();
	}
	else
	{
	    $sqlclause->log($main::LOG_ERR, "lookupauthgroup SQL query failed");
	    $user->get_check->add_attr('Auth-Type', 'Reject:AUTHGROUP lookup failure');
	    last;
	}
    }

    # If there was not at least one user/group with check or reply items, reject
    if (!$hits)
    {
	$sqlclause->log($main::LOG_ERR, "No GROUPAUTH entries found for username $username ($userdn), devicegroup $devicegroup. Rejecting");
	$user->get_check->add_attr('Auth-Type', 'Reject:No GROUPAUTH entries found');
    }
}
