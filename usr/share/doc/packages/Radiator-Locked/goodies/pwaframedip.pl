# pwaframedip.pl
#
# This hooks fixes a problem with Enterasys switches where Framed-IP-Address
# is not included in accounting packets, but the information is availble via
# SNMP when for Enterasys captive-portal (PWA) authentication
# 
# Users' IPs are stored by the PWA MIB on the switch. We can access this 
# directly since we have a partial index from the NAS-Port in the Acct 
# Request. This number is equal to the switch ifIndex which is one half of 
# the index to the etsysPwaAuthSessionIPAddress table in the MIB.
#
# We do not have the other half of the index (session ID) but we can combine
# the partial index with snmpgetnext to return the user's IP address.
#
# After retrieval the Framed-IP-Address is stored in an SQL table for later
# use. It is then added to the request packet so that Framed-IP-Address will
# be present when the Acct Request is proxied on (to a billing server)
# 
# The exception is when the hook is processing a Stop record. In this case 
# etsysPwaAuthSessionIPAddress has already been flushed of the user's IP. 
# But we can retrieve it from the SQL table using the Acct-Session-Id and 
# add it to the request as before. 
#
# The hook should also work when an Interim update is received with a new
# IP address.
#
# NOTES: 
# - This should be called by a PreAuthHook in the realm or handler
# - The multiauth feature on the switch should be disabled. Only one user per 
#   port is allowed or the index workaround will fail
#
# EXAMPLE:
# snmpgetnext -v2c -c <comm> 10.10.1.2 .1.3.6.1.4.1.5624.1.2.8.4.1.1.13.12009
# .1.3.6.1.4.1.5624.1.2.8.4.1.1.13.12009.4 = Hex-STRING: 81 CA 81 E2
#
# Author: Ben Carbery (ben.carbery@gmail.com)
#
sub {
    use DBI;

    my $p           = ${$_[0]};     # Request packet
    my $rp          = ${$_[1]};     # Response packet
    my $hook_file   = 'pwaframedip.pl';
    my $debug       = 0;
    my $ip;

    # Get attributes
    my $host                = &Radius::Util::inet_ntop($p->{RecvFromAddress});
    my $username            = $p->get_attr('User-Name');
    my $acct_session_id     = $p->get_attr('Acct-Session-Id');
    my $nas_ip              = $p->get_attr('NAS-IP-Address');
    my $type                = $p->get_attr('Acct-Status-Type');
    my $called_id           = $p->get_attr('Called-Station-Id');
    my $nas_port            = $p->get_attr('NAS-Port');
    my $nas_port_type       = $p->get_attr('NAS-Port-Type');

    # DB Credentials - defined in the Radiator config
    my $dbsource = &main::getVariable('dbsource');
    my $dbusername = &main::getVariable('dbusername');
    my $dbauth = &main::getVariable('dbauth');
    my $dbrel = 'pwa_sessions';

    # Check request matches intended use
    if ( $p->code() eq 'Accounting-Request' ) {
        # Debugging
        if ($debug) {
            use Data::Dumper;
            open (MYFILE, '>>/tmp/pwaframedip.debug');
            #print MYFILE Dumper( $p->{'Client'} );
            #print MYFILE Dumper( $p->{'Attributes'} );
            #print MYFILE Dumper( $p );
            close (MYFILE);
        }

        # Connect to DB
        my $dbh = DBI->connect_cached($dbsource, $dbusername, $dbauth) || die "connect_cached failed: $DBI::errstr";

        # Quoting for DBI
        my $q_username          = $dbh->quote($username);
        my $q_acct_session_id   = $dbh->quote($acct_session_id);
        my $q_nas_ip            = $dbh->quote($nas_ip);
        my $q_type              = $dbh->quote($type);
        my $q_called_id         = $dbh->quote($called_id);
        my $q_nas_port          = $dbh->quote($nas_port);
        my $q_nas_port_type     = $dbh->quote($nas_port_type);

        # Check accounting type
        if ($type !~ /Stop/) {

            ### Get Framed-IP-Address ###

            # SNMP vars
            my $snmpgetnext = '/usr/bin/snmpgetnext';
            my $oid_base    = '.1.3.6.1.4.1.5624.1.2.8.4.1.1.13';
            my $community   = $p->{Client}{'SNMPCommunity'};
            my $oid = "$oid_base" . '.' . "$nas_port";

            # Construct command
            my $command = "$snmpgetnext -v2c -c $community $host $oid";
            &main::log($main::LOG_DEBUG, "$hook_file: $username: SNMP command is: $command");

            # Run command
            #my $result = ".1.3.6.1.4.1.5624.1.2.8.4.1.1.13.12009.4 = Hex-STRING: 96 CB 81 E2\n";
            #my $result = "SNMPv2-SMI::enterprises.5624.1.2.8.4.1.1.13.27.1 = Hex-STRING: 82 38 03 02\n";
            my $result = `$command`;
            chomp $result;
            $result =~ s/\s$//g;
            &main::log($main::LOG_DEBUG, "$hook_file: $username: Result is: $result");

            # Check result
            if ($result =~ /error/i || $result =~ /no response/i || $result =~ /timeout/i) {
                &main::log($main::LOG_ERR, "$hook_file: $username: snmpgetnext failed: $command");
                return;

            # The risk with snmpgetnext is we get a result we are not interested in
            } elsif ( $result !~ /8.4.1.1.13/ ) {
                &main::log($main::LOG_ERR, "$hook_file: $username: IP is missing from PWA MIB: $command");
                return;
            }

            # Parse result, convert to IP Address
            $ip = substr($result, -11);
            $ip =~ s/ //g;
            $ip = join '.', unpack "C*", pack "H*", $ip;
            my $q_ip = $dbh->quote($ip);

            ### Store Framed-IP-Address ###

            my $select_statement = "SELECT username FROM $dbrel WHERE acct_session_id = $q_acct_session_id AND nas_ip_address = $q_nas_ip";
            my $insert_statement = "INSERT INTO $dbrel (acct_session_id, nas_ip_address, username, framed_ip_address, acct_status_type, called_station_id, nas_port, nas_port_type) VALUES ($q_acct_session_id, $q_nas_ip, $q_username, $q_ip, $q_type, $q_called_id, $q_nas_port, $q_nas_port_type)";
            my $update_statement = "UPDATE $dbrel SET framed_ip_address = $q_ip, acct_status_type = $q_type WHERE acct_session_id = $q_acct_session_id AND nas_ip_address = $q_nas_ip";

            # Check for existing entry
            &main::log($main::LOG_DEBUG, "$hook_file: $username: $select_statement");
            my ($user_check) = $dbh->selectrow_array($select_statement);

            if (defined $user_check) {
                &main::log($main::LOG_DEBUG, "$hook_file: $username: $update_statement");
                $dbh->do($update_statement) || die "$hook_file: UPDATE failed: $DBI::errstr";

            } else {
                &main::log($main::LOG_DEBUG, "$hook_file: $username: $insert_statement");
                $dbh->do($insert_statement) || die "$hook_file: INSERT failed: $DBI::errstr";
            }

        } elsif ($type =~ /Stop/) {

            ### Retrieve Framed-IP-Address ###

            my $select_statement = "SELECT framed_ip_address FROM $dbrel WHERE acct_session_id = $q_acct_session_id AND nas_ip_address = $q_nas_ip";
            my $delete_statement = "DELETE FROM $dbrel WHERE acct_session_id = $q_acct_session_id AND nas_ip_address = $q_nas_ip";

            # Retrieve stored Framed-IP-Address
            &main::log($main::LOG_DEBUG, "$hook_file: $username: $select_statement");
            ($ip) = $dbh->selectrow_array($select_statement);

            # Delete the session
            $dbh->do($delete_statement) || die "$hook_file: DELETE failed: $DBI::errstr";

            if (!defined $ip) {
                &main::log($main::LOG_ERR, "$hook_file: $username: Could not retrieve stored Framed-IP-Address for accounting session $acct_session_id");
                return;
            }
        }

        # Add attribute to request
        $p->add_attr('Framed-IP-Address', $ip);
        &main::log($main::LOG_INFO, "$hook_file: $username: Added Framed-IP-Address: $ip");

    } else {
        &main::log($main::LOG_ERR, "$hook_file: $username: Internal error: hook received non-Accounting-Request");
        return;

    }
}
