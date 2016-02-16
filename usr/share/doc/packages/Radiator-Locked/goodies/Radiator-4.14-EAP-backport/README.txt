2014-12-03

Instructions for applying the backport for the EAP bug fixed in
Radiator 4.14. See OSC security advisory OSC-SEC-2014-01 for more
information.

The backports are provided for Radiator versions older than 4.14.

The backports address only the EAP bug described in
OSC-SEC-2014-01. No other changes were backported. We recommend
upgrading to Radiator 4.14 if possible.


Notes on package managers
+++++++++++++++++++++++++
If you install the backport, make sure that when you upgrade Radiator
the next time, the backported EAP.pm is also upgraded. If you have
installed Radiator from a RPM package, make sure that during RPM
upgrade, the backported EAP.pm is also upgraded.


Compatibility notes
+++++++++++++++++++
Backport for Radiator 4.4 and earlier may cause authentication rejects
by triggering EAP context finding bug fixed in Radiator 4.5. This is
the last entry in the Radiator change history for release
4.5. Possible workarounds are using different values for the
EAPAnonymous configuration parameter and arranging the configuration
so that the User-Names do not collide.


Quick instructions
++++++++++++++++++
The backport is a single file called EAP.pm in the directory that
corresponds to your Radiator version.

Check that the Backport-Id at the beginning of your current EAP.pm
matches backported EAP.pm's Id. Sometimes people have multiple
versions installed.

Replace your current EAP.pm with the backported EAP.pm. Restart
Radiator


Full instructions
+++++++++++++++++
When Radiator starts up, it will log its version as shown below. The
debug level needs to be set to Trace 2 for the message to be logged.
   Tue Dec  2 17:55:19 2014: NOTICE: Server started: Radiator 4.13 on hostname

The backport is a single file called EAP.pm in the directory that
corresponds to your Radiator version. To install the backport, do the
following.

- determine Radiator version. Below 4.13 is used as an example.
- locate the current EAP.pm
- make a backup copy of the located file. For example: EAP.pm-Radiator-4.13
- verify that the Id at the beginning of the file matches backport file's Id.
  For Radiator-4.13 the Id is:    $ Id: EAP.pm,v 1.60 2012/06/18 22:29:33 mikem Exp $
  Backport file contains: $Backport-Id: EAP.pm,v 1.60 2012/06/18 22:29:33 mikem Exp $
- if the Ids matches, copy Radiator-4.10-4.13/EAP.pm over the located file
- restart all Radiator instances


Additional steps
++++++++++++++++
You may optionally remove EAP_16776957_4244372217.pm from your system
if it is still present. This file is never needed in production
environment.

$Id: README.txt,v 1.3 2014/12/03 08:03:10 hvn Exp $
