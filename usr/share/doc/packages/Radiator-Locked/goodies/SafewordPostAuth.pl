# SafewordPostAuth.pl
#
# PostAuthHook to munge user name and password
#  
# Author: Stephen Frede
# 
# Safeword authentication uses a username, password and token string.
# The Safeword Radius server expects "username,token" in the RADIUS user
# field and password in the password field.  However, for various
# reasons (mainly because the firewall needs to know the username),
# we have to present the username by itself in the RADIUS user field.
# We pass "token,password" in the password field.
# So we have to munge one form into the other.
#
# We do this by using the PreAuthHook and PostAuthHook hooks in Radiator.
#
# In an appropriate <AuthBy RADIUS> section in the configuration
# file, include the lines:
#	PreAuthHook file:"%D/SafewordPreAuth"
#	PostAuthHook file:"%D/SafewordPostAuth"
# Prior to passing the username and password to the Safeword Radius
# server for authentication, if the password is in the form
#	token-password ',' remembered-password
# where token-password is a 6-character string, then the token-password
# is stripped from the password field and appended (after a comma) to the
# username field.
#
# Similarly, after authentication, we put the username back the way it was,
# so that logging etc. will be OK.

sub 
{
    my $p = ${$_[0]};

    my $user = $p->getUserName;
    if ($user =~ /^(.*),......$/)
    {
	$p->changeUserName("$1");
	&main::log($main::LOG_DEBUG, "PostAuthHook: user=>'$1'");
    }
    return;
}

