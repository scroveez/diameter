# eap_anon_hook.pl
#
# This hook fixes the problem with some implementations of TTLS, where the
# accounting requests have the User-Name of anonymous, instead of the real
# users name. After authenticating the inner TTLS request, the
# as a PostAuthHook this caches the _real_ user name in an SQL table,
# As a PreProcessingHook it replaces the 'anonymous' user name in accounting requests with the 
# real user name that was previously cahed for the NAS and NAS-Port.
#
# The PreProcessingHook has to run in the outer Handler, and the PostAuthHook
# has to run in the inner Handler. 
#
# Will also work with PEAP, although it not often required, since most PEAP clients
# set the User-Name in the outer request to the real user name
#
# See goodies/eap_ttls.cfg and goodies/eap_peap.cfg for example configuration.
# There is a sample RADLASTAUTH table in goodies/mysqlCreate.sql
#
# Caution: You may need to adjust this code for different types of NAS.
# It was tested with the Odyssey client and a Cisco 340 Access Point.
# The 340 does not send Acct-Session-Id in the access requests, only in the 
# accounting requests. Your AP may be different.
#
# Author: Mike McCauley (mikem@open.com.au)
# Dont foget to change $dbsource, $dbusername and $dbauth to suit your database.
sub
{
    use DBI;
    my ($p, $rp, $handled, $reason) = @_;

    # Change these to suit your site:
    my $dbsource = 'dbi:mysql:radius';
    my $dbusername = 'mikem';
    my $dbauth = 'fred';

    # If there is a 3rd arg then we are being called as PostAuthHook
    if (defined $handled)
    {
	if (${$p}->code() eq 'Access-Request' && $$handled == 0 && ${$p}->{outerRequest})
	{
	    # This is in a PostAuthHook _after_ the inner Access-Request has been accepted, cache
	    # the _real_ user name, NAS port and Acct-Session-Id
	    my $dbh = DBI->connect_cached($dbsource, $dbusername, $dbauth)
		|| die "connect_cached failed: $DBI::errstr";
	    # The username is the EAP identitiy or the User-Name
	    my $username = ${$p}->{EAPIdentity};
	    $username = ${$p}->getUserName() unless defined $username;
	    $username = $dbh->quote($username);
	    my $nasidentifier = $dbh->quote(${$p}->{outerRequest}->getNasId());
	    my $nasport = ${$p}->{outerRequest}->getAttrByNum($Radius::Radius::NAS_PORT);
	    my $acctsessionid = $dbh->quote(${$p}->{outerRequest}->getAttrByNum($Radius::Radius::ACCT_SESSION_ID));
	    my $timestamp = time;
	    # Caution, this is SQL type specific. Not all SQLs support 'replace'
	    $dbh->do("replace into RADLASTAUTH (USERNAME, NASIDENTIFIER, NASPORT, ACCTSESSIONID, TIME_STAMP) values ($username, $nasidentifier, $nasport, $acctsessionid, $timestamp)") 
		|| die "replace failed: $DBI::errstr";
	}
    }
    else
    {
	if (${$p}->code() eq 'Accounting-Request' )
	{
	    # This is in a PreProcessingHook,_before_ an accounting request is processed.
	    # Replace User-Name (which is probably 'anonymous') with 
	    # the real user name we cached when they were accepted.
	    my $dbh = DBI->connect_cached($dbsource, $dbusername, $dbauth)
		|| die "connect_cached failed: $DBI::errstr";
	    my $nasidentifier = $dbh->quote(${$p}->getNasId());
	    my $nasport = ${$p}->getAttrByNum($Radius::Radius::NAS_PORT);
	    my $acctsessionid = $dbh->quote(${$p}->getAttrByNum($Radius::Radius::ACCT_SESSION_ID));
	    # Dont match Acct-Session-Id for Cisco 340 APs:
	    my ($username) = $dbh->selectrow_array("select USERNAME from RADLASTAUTH where NASIDENTIFIER=$nasidentifier and NASPORT=$nasport");
	    
	    # Now change the username in the accounting to the cached username
	    ${$p}->changeUserName($username) if defined $username;
	}
    }
}
