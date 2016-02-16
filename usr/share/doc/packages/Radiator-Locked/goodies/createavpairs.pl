# createavpairs.pl
#
# This hook converts all cisco-avpairs in the request
# into equivalent private RADIUS attributes, that can be stored to
# different SQL columns based on the private RADIUS attribute name.
# eg:
#         cisco-avpair = "task_id=62"
#         cisco-avpair = "timezone=UTC"
#         cisco-avpair = "service=shell"
#         cisco-avpair = "priv-lvl=0"
#         cisco-avpair = "cmd=exit <cr>"
# 
# becomes:
#       cisco-cmd = "task_id=62,timezone=UTC,service=shell,priv-lvl=0,cmd=exit <cr>"
# Author: Mike McCauley for NBNco
sub 
{
    my $p = ${$_[0]};
    my $cmd;
    if (my @avpair = $p->get_attr('cisco-avpair')) {
	foreach my $avpair (@avpair) {
	    $avpair =~ s/\0+$//; # Sometimes get trailing NULs in strings :=(
	    $cmd .= $avpair . ',';
	}
	$p->add_attr('cisco-cmd', $cmd);
    }
}
