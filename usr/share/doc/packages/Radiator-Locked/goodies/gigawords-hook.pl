# -*- mode: Perl -*-
# 
# 2004. Igor Briski, Iskon Internet d.d.
#
# ClientHook file:"%D/gigawords-hook.pl"
#
# Detects the presence of Acct-(Input|Output)-Gigawords
# and Acct-(Input|Output)-Octets attributes,
# calculates the new 64 bit integer values,
# and finally, adds the calculated 64 bit values to
# OSC-Input-Octets-64 and OSC-Output-Octets-64
# NB: these are 64 bit integers

sub 
{
    my $p = ${$_[0]};
    my $code = $p->code();
    
    return unless $code eq 'Accounting-Request';

    my ($ingiga, $inoctets, $newinoctets, $outgiga, $outoctets, $newoutoctets);

    if (defined($ingiga = $p->get_attr('Acct-Input-Gigawords')) &&
	defined($inoctets = $p->get_attr('Acct-Input-Octets')))
    {
        &main::log($main::LOG_DEBUG,
		   "Acct-Input-Gigawords attribute present, counter overflowed.");
	&main::log($main::LOG_DEBUG,
		   "Acct-Input-Gigawords = $ingiga, Acct-Input-Octets = $inoctets");
	
	$newinoctets = $inoctets + ($ingiga * 4294967296);
	$p->change_attr('OSC-Acct-Input-Octets', $newinoctets);
	
	&main::log($main::LOG_DEBUG,
		   "Calculated and added OSC-Acct-Input-Octets = $newinoctets");
    }
    
    if (defined($outgiga = $p->get_attr('Acct-Output-Gigawords')) &&
	defined($outoctets = $p->get_attr('Acct-Output-Octets')))
    {
	&main::log($main::LOG_DEBUG,
		   "Acct-Output-Gigawords attribute present, counter overflowed.");
	&main::log($main::LOG_DEBUG,
		   "Acct-Output-Gigawords = $outgiga, Acct-Output-Octets = $outoctets");
	
	$newoutoctets = $outoctets + ($outgiga * 4294967296);
	$p->change_attr('OSC-Acct-Output-Octets', $newoutoctets);
	
	&main::log($main::LOG_DEBUG,
		   "Calculated and added OSC-Acct-Output-Octets = $newoutoctets");
    }
    return;
}
