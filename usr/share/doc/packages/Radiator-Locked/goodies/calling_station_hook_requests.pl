# calling_station_hook_requests.pl
#
# This hook does three things:
#
# 1) Insert the Calling-Station-ID into the inner request
# 2) Insert the Called-Station-ID into the inner request
# 3) Insert the "outer" EAP identity into the inner request as "Outer-EAP-Id"
#
# This provides the ability to AuthLog inner authentication requests with
# the MAC address of the user authenticating with EAP types such as PEAP
# or TTLS where an anonymous outer identity might be allowed.
#
# Using this script, it is possible to get useable authentication logs, even
# from NAS devices that do not support accounting, or do not support it
# correctly.  (Such as the D-Link DWL-900AP+, Linksys WRT54G/WAP54G, HP 420).
#
# This script also has implications for tracking down users that are misusing
# the outer identity, since both the outer and inner id are availble in the log
# message.  :)
#
# Additionally, by using clever Identifiers in your handler, you can log the EAP
# type in use.  This could be handy for testing, or shops that need multiple EAP
# types.
#
# Author: Terry Simons (Terry.Simons@gmail.com)
# See goodies/eap_ttls.cfg for example configuration.
#

sub
{
     my ($p, $rp, $handled, $reason) = @_;

     # If there is a 3rd arg then we are being called as PostAuthHook
     if (defined $handled)
     {
         if (${$p}->code() eq 'Access-Request' && ${$p}->{outerRequest})
         {
             # RFC 3580 specifies a particular format for Calling-Station-Id and
             # Called-Station-Id formats.  We ought to go ahead and convert to be RFC compliant

             ${$p}->addAttrByNum($Radius::Radius::CALLING_STATION_ID, ${$p}->{outerRequest}->getAttrByNum($Radius::Radius::CALLING_STATION_ID));
             ${$p}->addAttrByNum($Radius::Radius::CALLED_STATION_ID, ${$p}->{outerRequest}->getAttrByNum($Radius::Radius::CALLED_STATION_ID));

             ${$p}->add_attr('Outer-EAP-Id', ${$p}->{outerRequest}->get_attr('User-Name'));
         }
     }
}
