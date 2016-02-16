# sip2hook.pl
#
# Sample SIP2Hook which checks the received Patron Status Response or
# Patron Information Response for AF (screen message) field
# indicating the user should not be allowed to log in.
#
# The hook return value must be one of $main::ACCEPT, $main::REJECT,
# $main::IGNORE, $main::CHALLENGE or $main::REJECT_IMMEDIATE.
#
# The password check follows when the return code is $main::ACCEPT.
#
# Note: When configured with NoCheckPassword parameter, the hook can
# be used for all authentication and authorisation checks.

sub
{
    my $self = $_[0];     # Handle to the current AuthBy SIP2 object
    my $response = $_[1]; # Received Patron Status or Information Response
    my $p = $_[2];        # Reference to the current request

    my $af = $self->sip_decode_field('AF', $response);
    $self->log($main::LOG_DEBUG, "SIP2 AF field = $af");

    if ($af =~ /BARRED|ALERT|BLOCKED/)
    {
        return ($main::REJECT, "Access rejected by SIP2Hook: $af");
    }

    return ($main::ACCEPT, "Accepted by SIP2Hook");
}
