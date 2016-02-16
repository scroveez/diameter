# -*- mode: Perl -*-
# AlterNASPort
#
# This is to change the Cisco-NAS-Port to NAS-port so we can
# use the standard session database and NasType Cisco.
#
# Requires the use of the following Cisco configuration:
#
#       radius-server vsa send accounting
#       radius-server vsa send authentication
#
# Contributed by Paul Pilsbury <ppilsbur@connect.com.au>.
#


sub
{
         my $p = ${$_[0]};


        my $nasport = $p->get_attr('Cisco-NAS-Port');
        my $nasip = $p->get_attr('NAS-IP-Address');
        my $user = $p->get_attr('User-Name');


        my $orignasport = $nasport;


        if (defined($nasport))
        {
                my $new_nas_port;
                my $port_no;
                my $slot;
                my $port;


                $new_nas_port  =  $nasport;


                # Looking for Async9/96*Serial13/18:14
                # This is what the 5850 sends and i dont have the ports
                # per slot to work this out.
                # also it doesnt have the MIB in our 5850's for the query


                if ($new_nas_port =~ /Async(\d+)\/(\d+)\*Serial/)
                {
                        $port_no = "$2";
                }


                # port looks like Async8/24
                elsif ( $new_nas_port =~ /Async(\d+)\/(\d+)/)
                {
                        $slot = $1 + 1;
                        $port = $2;
                        $port_no = $slot * 108 + $port;
                }


                # port looks like tty1/24
                elsif ( $new_nas_port =~ /tty(\d+)\/(\d+)/)
                {
                        $slot = $1 + 1;
                        $port = $2;
                        $port_no = $slot * 108 + $port;
                }


                # looks like Async19
                elsif ( $new_nas_port =~ /Async(\d+)/)
                {
                        $port_no = $1;
                }


                # looks like tty57
                elsif ( $new_nas_port =~ /tty(\d+)/)
                {
                        $port_no = $1;
                }


                else
                {
                        &main::log($main::LOG_INFO,
                                "Nothing found in script AlterNASPort $user $nasip");
                }


                $p->change_attr('NAS-Port', $port_no) ;


                # for debug and testing
                &main::log($main::LOG_INFO,
                        "Orig-NAS-Port = $orignasport NAS-Port = $port_no
                        Slot = $slot Port = $port User-Name = $user
                        NAS-IP-Address = $nasip");
        }
}







