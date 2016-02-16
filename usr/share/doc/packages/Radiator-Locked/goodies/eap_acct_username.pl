# eap_acct_username.pl
# This hook fixes the problem with some implementations of TTLS, where the
# accounting requests have the User-Name of anonymous, instead of the real
# users name. 
# Example configuration:
# 
# <Handler Realm=domain.tld>
#         RewriteUsername s/^([^@]+).*/$1/
#         AuthBy static_users
#        PostProcessingHook file:"/home/radius/etc/eap_acct_username.pl"
# </Handler>
# Contributed by Rok Papež

sub
{
	my ($req, $rep, $handled, $reason) = @_;
	if (${$rep}->code() eq 'Access-Accept' )
	{
		my $req_username = ${$req}->{EAPIdentity};
		$req_username = ${$req}->getUserName() unless defined $req_username;
		if($req_username =~ m/^anonymous@(.*)$|^anonymous$|^@(.*)$/i) {
			my $realm;
			# This is outer replay.
			# If we did have a realm, append it now.
			$realm = $1 if defined $1;
			$realm = $2 if defined $2;
			if(!defined($realm)) {
				return;
			}
			${$rep}->changeUserName(${$rep}->getUserName() . "\@" . $realm);
		} else {
			# Inner reply, copy the username to outer request (without realm).
			${$rep}->changeUserName($req_username) if defined $req_username;
		}
	}
}
