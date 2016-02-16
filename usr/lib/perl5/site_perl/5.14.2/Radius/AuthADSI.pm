# AuthADSI.pm
#
# Object for handling Authentication through Microsoft
# Active Directory Service Interface.
#
# Using this module you can authenticate users through
# any Active Directory service, such as WinNT, LDAP, etc
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 2000 Open System Consultants
# $Id: AuthADSI.pm,v 1.23 2007/12/18 21:23:50 mikem Exp $

package Radius::AuthADSI;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Win32::OLE qw(in);
use strict;

# RCS version number of this module
$Radius::AuthADSI::VERSION = '$Revision: 1.23 $';

# This keeps a copy of the group names of the last user found locally
my @groups_of_last_user_found;

if ($^O ne 'MSWin32')
{
    &main::log($main::LOG_ERR, 
	       "AuthBy ADSI is only available on Windows platforms");
}

%Radius::AuthADSI::ConfigKeywords = 
('BindString'          => 
 ['string', 'Defines what ADSI object will be bound in order to get user details. You can bind to any Active Directory provider supported on your Radiator host, but WinNT or LDAP will be the usual choices. ', 0],
 'AuthUser'            => 
 ['string', 'Defines how to contruct the Active Directory user name to be authenticated by Active Directory. You can choose whether to use standard NTLM user names or AD Distinguished Names. This is a different concept to BindString, which specifies what AD object to get account details from.', 0],
 'AuthFlags'           => 
 ['integer', 'specifies flags to be passed to OpenDSObject. The default is 1, which means NTLM secure authentication. You need to specify 0 to use an Active Directory DN in AuthUser.', 1],
 'CheckGroup'          => 
 ['stringarray', 'This optional parameter, in conjunction with CheckGroupServer, allows you to set a Class reply attribute that depends on which NT group the user is a member of. CheckGroup is a comma-separated pair of names. The first is an NT group name, the second is an arbitrary string. During authentication, if the user is a member of the NT group, then the Class attribute in the reply will be set to the arbitrary string. The first match found will be used.', 1],
 'AuthAttrDef'         => 
 ['stringhash', 'allows you to use additional ADSI user information as Radius check or reply items. This is most useful when you define new user attributes in your Active Directory schema.', 1],
 'GroupRequired'	   => 
 ['string', 'Specifies a group name. In order to authenticate the user must be a member of the named group', 1],
 'SearchAttribute'	   => 
 ['string', 'If SearchAttribute is defined, it specifies the LDAP attribute to search against.  It will find a user where SearchAttribute = AuthUser. For example, to search for the userPrincipalName (which is the user@domain.com style of name), you would define SearchAttribute as "userPrincipalName"', 1],
 );

# RCS version number of this module
$Radius::AuthADSI::VERSION = '$Revision: 1.23 $';

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{BindString}          = 'WinNT://%0,User';
    $self->{GroupBindString}     = 'WinNT://%0,Group';
    $self->{GroupUserBindString} = 'WinNT://%1';
    $self->{AuthUser}            = '%0';
    $self->{AuthFlags}           = 1;
}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet
# Accounting is ignored
# Access requests are validated by checking the user password
# only. No check items are checked, no reply
# items are returned
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;

    $self->log($main::LOG_DEBUG, "Handling with ADSI", $p);

    if ($p->code eq 'Access-Request')
    {
	return ($main::IGNORE, "Ignored due to IgnoreAuthentication")
	    if $self->{IgnoreAuthentication};

	my $user_name = $p->getUserName;
	$user_name =~ s/@[^@]*$//
	    if $self->{UsernameMatchesWithoutRealm};
	my $password = $p->decodedPassword();

	# First we need to bind to the ADSI object. $bindstring
	# is the name of the object to bind to. In order to bind,
	# we extract the provider name (eg the WinNT: or LDAP: at 
	# the beginning), do a GetObject on that, then use
	# GetDSObject with the username and password
	my $bindstring = &Radius::Util::format_special
	    ($self->{BindString}, $p, undef, $user_name);
	$self->log($main::LOG_DEBUG, "BindString converted to $bindstring", $p);
	my $namespace;
	$namespace = $1 if $bindstring =~ /^(.+:)/;
	if (!$namespace)
	{
	    $self->log($main::LOG_ERR, "Could not find provider name in BindString", $p);
	    return ($main::REJECT, 'Namespace configuration problem');
	}

	# Some AD providers have special requirements for
	# generating the name of the user to be authenticated
        # see http://msdn.microsoft.com/library/psdk/adsi/if_core_3uic.htm
	my $auth_user = &Radius::Util::format_special
	    ($self->{AuthUser}, $p, undef, $user_name);
	$self->log($main::LOG_DEBUG, "AuthUser converted to $auth_user", $p);

	# Are we searching for user with a specific LDAP attribute?  
	# If so, set the bindstring to the fully distringuished LDAP name using an ADODB search
	# if not, we just fall through with the bindstring as the user entered it.
	# Contributed by Mark Motley (mark@motleynet.com)
	if (($namespace eq "LDAP:") && (defined $self->{SearchAttribute})) 
	{
	    $self->log($main::LOG_DEBUG,"Starting ADODB search for $self->{SearchAttribute} = $auth_user", $p);
	    $bindstring = $namespace . '//' 
		. GetUserDN($self->{SearchAttribute}, $auth_user, $self->{BindString});
	    return($main::REJECT, 'General error in ADODB search')
		if $bindstring eq 'LDAP://error';
	    return($main::REJECT, 'User not found in AD')
		if $bindstring eq 'LDAP://notfound';
	    $self->log($main::LOG_DEBUG, "User found at $bindstring", $p);
	}

	# If using LDAP, bindstring now contains the DN.  
	# Other providers (e.g. WinNT) are whatever was
	# passed from the config file.
	$self->log($main::LOG_DEBUG, "Connecting to namespace: $namespace", $p);
	my $ons = Win32::OLE->GetObject($namespace);
	if (!$ons)
	{
	    $self->log($main::LOG_ERR, "Could not get namespace object for $namespace: " 
		       . Win32::OLE->LastError(), $p);
	    return ($main::REJECT, 'Configuration problem');
	}

	# ..and now open up the user object
	$self->log($main::LOG_DEBUG, "Running OpenDSObject on $bindstring", $p);
	my $ouser = $ons->OpenDSObject($bindstring, 
				       $auth_user,
				       $password,
				       $self->{AuthFlags});
	if (!$ouser)
	{
	    $self->log($main::LOG_DEBUG, "Could not get user object: " 
		       . Win32::OLE->LastError(), $p);
	    return ($main::REJECT, 'Could not find user');
	}

	# Check common problems and reject as necessary
	return ($main::REJECT, 'Account is disabled')
	    if ($ouser->{AccountDisabled});
	return ($main::REJECT, 'Account is Locked')
	    if ($ouser->{IsAccountLocked});
	return ($main::REJECT, 'Outside allowed login hours')
	    unless $self->checkLoginHours($ouser->{LoginHours});

	# Get the names of all the groups this user is in
	@groups_of_last_user_found = ();
	foreach (in $ouser->Groups)
	{
	    push(@groups_of_last_user_found, $_->Name());
	}

	# If GroupRequired is set, make sure our user is a member
	return ($main::REJECT, "Not member of group $self->{GroupRequired}")
	    if defined $self->{GroupRequired} && !$self->userIsInGroup($user_name, $self->{GroupRequired}, $p);

	# Begin CheckGroup group checking for Class reply attributes
	if (defined $self->{CheckGroup})
	{
	    my $ref;
	    foreach $ref (@{$self->{CheckGroup}}) 
	    {
		my ($adsigroupname, $adsigroupreply) = split(/\s*,\s*/, $ref, 2);
		foreach (@groups_of_last_user_found)
		{
		    if ($_ eq $adsigroupname)
		    {
			$self->log($main::LOG_DEBUG, "$auth_user is member of $adsigroupname group, assigning Class $adsigroupreply", $p);
			$p->{rp}->add_attr("Class", $adsigroupreply);
			last;
		    }
		}
	    } 
	}
	
	# Now check any AuthAttrDefs there may be
	# Find all the check and reply attributes 
	# and save them for later.
	my $adsiname;
	my $checkattrs = Radius::AttrVal->new();
	my $replyattrs = Radius::AttrVal->new();
	foreach $adsiname (keys %{$self->{AuthAttrDef}})
	{
	    my $val = $ouser->{$adsiname};

	    next unless defined $val; # Not present
	    # Caution, $ouser->{$adsiname} could be an array value
	    my @vals;
	    if (ref $val eq 'ARRAY')
	    {
		@vals = @$val;
	    }
	    else
	    {
		push(@vals, $val);
	    }
	    
	    my ($attrib, $type) = split(/,\s*/, $self->{AuthAttrDef}{$adsiname});
	    $type = lc($type); # lower-casify
	    if ($type eq 'check') 
	    {
		if ($attrib eq 'GENERIC')
		{
		    $checkattrs->parse(@vals);
		}
		else 
		{
		    # Permit alternation from multivalued attrs
		    $checkattrs->add_attr($attrib, join('|', @vals));
		}
	    }
	    elsif ($type eq 'reply')
	    {
		if ($attrib eq 'GENERIC')
		{
		    $replyattrs->parse(@vals);
		}
		else
		{
		    map {$replyattrs->add_attr($attrib, $_)} @vals;
		}
	    }
	    elsif ($type eq 'request')
	    {
		if ($attrib eq 'GENERIC')
		{
		    $p->parse(join ',', @vals);
		}
		else
		{
		    map {$p->add_attr($attrib, $_)} @vals;
		}
	    }
	}

	# Check the reply attributes
	my ($checkResult, $reason)
	    = $self->checkAttributes($checkattrs, $p);
	return ($checkResult, $reason) 
	    unless $checkResult == $main::ACCEPT;
	
	# Check any extra check items
	if ($extra_checks)
	{
	    ($checkResult, $reason)
		= $self->checkAttributes($extra_checks, $p);
	    return ($checkResult, $reason) 
		unless $checkResult == $main::ACCEPT;
	}

	# Success, the password and check items must be right
	# Add any reply attributes from AuthAttrDef
	$p->{rp}->add_attr_list($replyattrs);
	
	# Add and strip attributes before replying
	$self->adjustReply($p);
	
	$p->{Handler}->logPassword($user_name, $password, 'ADSI', 1, $p) if $p->{Handler};
	return ($main::ACCEPT);
    }
    else
    {
	return ($main::IGNORE, "Ignored due to IgnoreAccounting")
	    if $self->{IgnoreAccounting};

	# Might be an Accounting-Request, or something else
	# Send a generic reply on our behalf
	return ($main::ACCEPT);
    }
}

#####################################################################
# Check if the user is in the group
# $user is a user name and $group is a group name
sub userIsInGroup
{
    my ($self, $user, $group, $p) = @_;

    foreach (@groups_of_last_user_found)
    {
	return 1 if ($_ eq $group);
    }
    
    return;
}

#####################################################################
# This routine searches AD via ADODB to find the distinguishedName of the user specified
# by the userPrincipalName (UPN).
# Thanks to Kelvin Param for an article on perl.com ("Building a Bridge to the Active
# Directory") that helped here, I really took his code and modified it to suite my needs.
sub GetUserDN 
{
    my $strAttributeName=shift(@_); #could be cn, userPrincipalName, etc
    my $strAttributeValue=shift(@_); #could be cn value, userPrincipalName value, etc
    my $strADsPath=shift(@_);
    my $dn;
    my $strProvider="Active Directory Provider";
    my $strConnectionString=$strProvider;
    my $strFilter="(" . $strAttributeName . "=" . $strAttributeValue . ")";
    my $strAttribs="distinguishedName"; 
    my $strScope="subtree";
    my $strCommandText="<" . $strADsPath . ">;" . $strFilter . ";" . $strAttribs . ";" . $strScope;
    my $objConnection = Win32::OLE->new ("ADODB.Connection") or return "errornewcon";
    my $objRecordset = Win32::OLE->new ("ADODB.Recordset") or return "errornewrec";
    my $objCommand = Win32::OLE->new ("ADODB.Command") or return "errornewcmd";
    
    $objConnection->{Provider} = ("ADsDSOObject");
    $objConnection->{ConnectionString} = ($strConnectionString);
    $objConnection->Open();
    $objCommand->{ActiveConnection} = ($objConnection);
    $objCommand->{CommandText} = ($strCommandText);
    $objRecordset = $objCommand->Execute($strCommandText) or return "errorexec";

    return "Bad recordset"
	unless $objRecordset;

    if ($objRecordset->EOF) {
         $dn = "notfound";
    } else {
        $dn = $objRecordset->Fields('distinguishedName')->value;
    }    

    $objCommand->Close;
    $objRecordset->Close;
    $objConnection->Close;

    return $dn;
}
1;
