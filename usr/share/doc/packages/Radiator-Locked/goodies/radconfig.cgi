#!/usr/bin/perl
# radconfig.cgi
#
# CGI script to configure a Radiator radius server
# by editing the Radiator configuration file

use CGI;
strict;

my $q = new CGI;
my $myself = $q->script_name;

# ------------------------------------------------------------
# Configurable variables

# The name of the Radiator configuration file
$filename = '/usr/local/etc/raddb/radius.cfg';
#$filename = '/usr/local/projects/Radiator/radius.cfg';
#$filename = '/tmp/radius.cfg';

# Locally configurable HTML setup. You can change these to set up your own
# particular look and feel
$localheader = '<body bgcolor=white>';
$localfooter = '</body>';
$toolBar = "<h1>Radiator Configuration</h1><a href=$myself>Top</a> File: <a href=$myself?_item=global_showconfig>$filename</a>";

#Email address of the administrator
$adminAddress = 'webmaster';

# Some global formatting attributes
# Table heading attribtues and font
$tha = 'align=right bgcolor=#0000C0';
$thf = 'color=white';

# The URL for the Radiatror HTML reference manual, if its 
# available on your system
$userHelpDoc = '/Radiator/ref.html';

# End of Configurable variables
# ------------------------------------------------------------

# Read the current config file into a data structure
&readConfig($filename, \%globalconfig);
#&dumpConfig(*STDOUT, \%globalconfig);

my %tracelevels = 
    (
     0 => 'Error (0)', 
     1 => 'Warning (1)', 
     2 => 'Notice (2)', 
     3 =>'Info (3)', 
     4 => 'Debug (4)', 
     5 =>'Packet Dump (5)'
     );

my @dbmtypes = qw(AnyDBM_File NDBM_File DB_File GDBM_File SDBM_File ODBM_File);
my @authbypolicies = qw(ContinueWhileIgnore ContinueUntilIgnore ContinueWhileAccept ContinueUntilAccept ContinueWhileReject ContinueUntilReject ContinueAlways);

# Here we describe the UI for each type of AuthBy
my %authbyuidescs = 
    (
     'CDB' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Filename', 'File name', '%D/users.cdb', 'text', '', 50],
       ['AcceptIfMissing', 'Accept if the user name is not present', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from a CDB database. 
It requires the CDB_File module from <a href=http://www.perl.com/cpan>CPAN</a>.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'DBFILE' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Filename', 'File name', '%D/users', 'text', '', 50],
       ['AcceptIfMissing', 'Accept if the user name is not present', 0, 'checkbox', ''],
       ['DBType', 'DBM type', 'AnyDBM_File', 'menu', '', \@dbmtypes],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from a DBM file. You can alter the type of DBM file to use,
but we recommend you use AnyDBM_File, which will choose the best format
for your platform
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'DYNADDRESS' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Allocator', 'Allocator', undef, 'text', '', 50],
       ['PoolHint', 'Address pool hint', '%{Reply:PoolHint}', 'text', '', 50],
       ['MapAttribute', 'Map values to reply attributes', undef, 'textn', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
allocate IP addresses from an address allocation module. At present, only
SQL databases are supported, and must be configured manually. 
<b>Allocator</b> is the Identifier of the Address Allocation module to use.
<b>Address pool hint</b> tells the address allocator how to select the 
address pool to use. The default hint is %{Reply:PoolHint}, which means 
a PoolHint reply attribute, that would need to be set by a preceeding
authentication module. <b>Map values to reply attributes</b> allows you
to return allocator-dependent values. The default ones are yiaddr 
returned as Framed-IP-Address and subnetmask returned as Framed-IP-Netmask. 
There may be other values available depending on the allocator you
are using',
      },

     'EMERALD' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['DBSource', 'Database sources', undef, 'textn', '', 50],
       ['DBUsername', 'Database user names', undef, 'textn', '', 50],
       ['DBAuth', 'Database passwords', undef, 'textn', '', 50],
       ['Timeout', 'SQL access timeout', undef, 'text', '', 50],
       ['FailureBackoffTime', 'SQL failure backoff time', undef, 'text', '', 50],
       ['AccountingTable', 'Accounting Table name', 'ACCOUNTING', 'text', '', 50],
       ['AuthSelect', 'SQL authentication query additional columns', undef, 'text', '', 50],
       ['EncryptedPassword', 'Password field is encrypted', 0, 'checkbox', ''],
       ['AccountingStartsOnly', 'Store accounting starts only', 0, 'checkbox', ''],
       ['AccountingStopsOnly', 'Store accounting stops only', 0, 'checkbox', ''],
       ['AuthColumnDef', 'Authentication query column definitions', undef, 'textn', '', 50],
       ['AcctColumnDef', 'Accounting column definitions', undef, 'textn', '', 50],
       ['AcctSQLStatement', 'Extra accounting query', undef, 'text', '', 50],
       ['TimeBanking', 'Use time banking', 0, 'checkbox', ''],
       ['AddATDefaults', 'Add (not replace) account type configs', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from the <a href=http://www.iea-software.com>Emerald</a>
or <a href=http://www.boardtown.com>Platypus</a> billing packages.
If using Platypus, requires the Platypus RadiusNT extensions to be installed.
<b>Database sources</b> is the name of the databse source, in the format
<code>dbi:drivername:parameters</code>. The drivername depends on the
perl DBD drivers you have installed, and the parameters depend on the 
DBD driver you are using. <b>Database user names</b> depends on which DBD
driver you are using, but is normally the name of the database username.
<b>Database passwords</b> depends on which DBD
driver you are using, but is normally the password for the database user 
name.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'EXTERNAL' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Command', 'Command line', undef, 'text', '', 50],
       ['DecryptPassword', 'Pass decrypted password', 0, 'checkbox', ''],
       ['ResultInOutput', 'Output of command contains result code', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from an external program. <b>Command line</b> is the full path
to the program you wish to run, including any arguments. 
The command will be passed the Radius
attributes from the incoming request on STDIN.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'FILE' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Filename', 'File name', '%D/users', 'text', '', 50],
       ['NoCache', 'Dont cache', 0, 'checkbox', ''],
       ['AcceptIfMissing', 'Accept if the user name is not present', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],

       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from a flat file in standard Radius user file format.
<b>File name</b>is the full path name of the users file. If 
<b>Dont cache</b> is set, Radiator will reread the users file for every
authentication.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'GROUP' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['AuthByPolicy', 'Authentication policy', 'ContinueWhileIgnore', 'menu',  '', \@authbypolicies],
       ['AuthBy', 'Authentication methods', undef, 'menun', '', [&getAuthByIdentifiersList()]],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from a series of other authentication modules. It will
authenticate from each of the modules identified by 
<b>Authentication methods</b> until the <b>Authentication policy</b>
is satisfied. The <b>Authentication methods</b> menu specifies the 
Identifier of AuthBy modules that you have previously configured.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'LDAP' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Host', 'LDAP server host name', 'localhost', 'text', '', 50],
       ['Port', 'LDAP server port', 389, 'text', '', 50],
       ['UseSSL', 'Use secure sockets', 0, 'checkbox', ''],
       ['BaseDN', 'Base DN for searching', undef, 'text', '', 50],
       ['AuthDN', 'DN of LDAP admin user', undef, 'text', '', 50],
       ['AuthPassword', 'Password of LDAP admin user', undef, 'text', '', 50],
       ['UsernameAttr', 'Name of LDAP attribute that holds the user name', 'uid', 'text', '', 50],
       ['PasswordAttr', 'Name of LDAP attribute that holds plaintext password', 'userPassword', 'text', '', 50],
       ['EncryptedPasswordAttr', 'Name of LDAP attribute that holds encrypted password', undef, 'text', '', 50],
       ['CheckAttr', 'Name of LDAP attribute that holds optional Radius check attributes', undef, 'text', '', 50],
       ['ReplyAttr', 'Name of LDAP attribute that holds optional Radius reply attributes', undef, 'text', '', 50],
       ['HoldServerConnection', 'Hold LDAP server connection as long as possible', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from an LDAP server. It is now obsolete. AuthBy LDAP2
should be used instead.
<b>Base DN</b> is the distinguised name of where to search for
user names. It would typically be something like 
<code>o=Open System Consultants, c=AU</code>.
<b>DN of LDAP admin user</b> is the DN of the LDAP user with 
administrative powers, and <b>Password of LDAP admin user</b>
is their LDAP password.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'LDAP2' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Host', 'LDAP server host name', undef, 'text', '', 50],
       ['Port', 'LDAP server port', 389, 'text', '', 50],
       ['UseSSL', 'Use secure sockets', 0, 'checkbox', ''],
       ['BaseDN', 'DN for start of searces', undef, 'text', '', 50],
       ['AuthDN', 'DN of LDAP admin user', undef, 'text', '', 50],
       ['AuthPassword', 'Password of LDAP admin user', undef, 'text', '', 50],
       ['UsernameAttr', 'Name of LDAP attribute that holds the user name', 'uid', 'text', '', 50],
       ['PasswordAttr', 'Name of LDAP attribute that holds plaintext password', 'userPassword', 'text', '', 50],
       ['EncryptedPasswordAttr', 'Name of LDAP attribute that holds encrypted password', undef, 'text', '', 50],
       ['CheckAttr', 'Name of LDAP attribute that holds optional Radius check attributes', undef, 'text', '', 50],
       ['ReplyAttr', 'Name of LDAP attribute that holds optional Radius reply attributes', undef, 'text', '', 50],
       ['HoldServerConnection', 'Hold LDAP server connection as long as possible', 0, 'checkbox', ''],
       ['Debug', 'Debug', 0, 'checkbox', ''],
       ['ServerChecksPassword', 'LDAP server checks users password', 0, 'checkbox', ''],
       ['AuthAttrDef', 'Map LDAP attribtues to Radius attributes', undef, 'textn', '', 50],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from an LDAP server using the perl-ldap module Net::LDAP
from <a href=http://www.perl.com/cpan>CPAN</a> or <a href=http://www.activestate.com>ActiveState</a>.
<b>Base DN</b> is the distinguised name of where to search for
user names. It would typically be something like 
<code>o=Open System Consultants, c=AU</code>.
<b>DN of LDAP admin user</b> is the DN of the LDAP user with 
administrative powers, and <b>Password of LDAP admin user</b>
is their LDAP password.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'LDAPSDK' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Host', 'LDAP server host name', undef, 'text', '', 50],
       ['Port', 'LDAP server port', 389, 'text', '', 50],
       ['UseSSL', 'Use secure sockets', 0, 'checkbox', ''],
       ['BaseDN', 'DN for start of searces', undef, 'text', '', 50],
       ['AuthDN', 'DN of LDAP admin user', undef, 'text', '', 50],
       ['AuthPassword', 'Password of LDAP admin user', undef, 'text', '', 50],
       ['UsernameAttr', 'Name of LDAP attribute that holds the user name', 'uid', 'text', '', 50],
       ['PasswordAttr', 'Name of LDAP attribute that holds plaintext password', 'userPassword', 'text', '', 50],
       ['EncryptedPasswordAttr', 'Name of LDAP attribute that holds encrypted password', undef, 'text', '', 50],
       ['CheckAttr', 'Name of LDAP attribute that holds optional Radius check attributes', undef, 'text', '', 50],
       ['ReplyAttr', 'Name of LDAP attribute that holds optional Radius reply attributes', undef, 'text', '', 50],
       ['HoldServerConnection', 'Hold LDAP server connection as long as possible', 0, 'checkbox', ''],
       ['ServerChecksPassword', 'LDAP server checks users password', 0, 'checkbox', ''],
       ['AuthAttrDef', 'Map LDAP attribtues to Radius attributes', undef, 'textn', '', 50],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
              
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from an LDAP server using the Netscape LDAP SDK
and their PerLDAP interface.
<b>Base DN</b> is the distinguised name of where to search for
user names. It would typically be something like 
<code>o=Open System Consultants, c=AU</code>.
<b>DN of LDAP admin user</b> is the DN of the LDAP user with 
administrative powers, and <b>Password of LDAP admin user</b>
is their LDAP password.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'NISPLUS' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Table', 'NIS Table', 'passwd.org_dir', 'text', '', 50],
       ['Query', 'NIS Query', '[name=%n]', 'text', '', 50],
       ['EncryptedPasswordField', 'Name of the encrypted password field', 'passwd', 'text', '', 50],
       ['AuthFieldDef', 'Authentication field definition', undef, 'text', '', 50],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from NIS+. It requires the NISPlus perl module from 
<a href=http://www.perl.com/cpan>CPAN</a>. <b>NIS Table</b> is the name 
of the NIS table to search. <b>NIS Query</b> says how users are to be 
located in the NIS+ table. It is a list of field=value pairs. The
defaults will find the user name in a standard NIS+ passwd table.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'NT' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Domain', 'NT Domain name', undef, 'text', '', 50],
       ['DomainController', 'Host name of Primary Domain Controller', undef, 'text', '', 50],
       ['HonourDialinPermission', 'Check dialin permissions too', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from an NT User Manager database, either from Unix or NT. 
ON unix, requires that the Authen-Smb perl module from 
<a href=http://www.perl.com/cpan>CPAN</a>.
<b>NT Domain name</b> is the name of the NT domain where your users are registered. <b>Primary Domain Controller</b> allows you to specify the host 
name of your Primary Domain Controller. If you don\'t specify 
it when running Radiator on NT, Radiator will attempt to determine the 
name of your Primary Domain Controller by polling the network. 
You would not normally need to set this when running Radiator on NT. 
If you do set it, it must be set to the network name of the domain 
controller, including the leading backslashes (\). 
ON Unix it <i>must</i> be set to the DNS name of the PDC host.
If <b>Check dialin permissions too</b> is selected, AuthBy NT will 
honour the "Grant dialin permission to user" flag, which can be found 
in the Dialin page of the NT User Manager.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies. 
',
      },

     'PAM' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Service', 'PAM Service name', 'login', 'text', '', 50],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from any PAM (Pluggable Authentication Module) module
supported on your host. It requires that PAM be installed and configured 
on your host, and it also requires the Perl module Authen-PAM-0.04 
or later from <a href=http://www.perl.com/cpan>CPAN</a>. 
<b>PAM Service Name</b>specifies the PAM 
service to be used to authenticate the user name.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'PLATYPUS' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['DBSource', 'Database sources', undef, 'textn', '', 50],
       ['DBUsername', 'Database user names', undef, 'textn', '', 50],
       ['DBAuth', 'Database passwords', undef, 'textn', '', 50],
       ['Timeout', 'SQL access timeout', undef, 'text', '', 50],
       ['FailureBackoffTime', 'Failure backoff time', undef, 'text', '', 50],
       ['AccountingTable', 'Accounting Table name', 'radiusdat', 'text', '', 50],
       ['AuthSelect', 'Additional columns for SQL authentication query', '', 'text', '', 50],
       ['EncryptedPassword', 'Password field is encrypted', 0, 'checkbox', ''],
       ['AccountingStartsOnly', 'Store accounting starts only', 0, 'checkbox', ''],
       ['AccountingStopsOnly', 'Store accounting stops only', 0, 'checkbox', ''],
       ['AuthColumnDef', 'Authentication query extra column definitions', undef, 'textn', '', 50],
       ['AcctColumnDef', 'Accounting column definitions', undef, 'textn', '', 50],
       ['AcctSQLStatement', 'Extra accounting query', undef, 'text', '', 50],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from the <a href=http://www.boardtown.com>Platypus</a> 
billing package.
<b>Database sources</b> is the name of the databse source, in the format
<code>dbi:drivername:parameters</code>. The drivername depends on the
perl DBD drivers you have installed, and the parameters depend on the 
DBD driver you are using. <b>Database user names</b> depends on which DBD
driver you are using, but is normally the name of the database username.
<b>Database passwords</b> depends on which DBD
driver you are using, but is normally the password for the database user 
name.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'PORTLIMITCHECK' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['DBSource', 'Database sources', undef, 'textn', '', 50],
       ['DBUsername', 'Database user names', undef, 'textn', '', 50],
       ['DBAuth', 'Database passwords', undef, 'textn', '', 50],
       ['Timeout', 'SQL access timeout', undef, 'text', '', 50],
       ['FailureBackoffTime', 'Failure backoff time', undef, 'text', '', 50],
       ['CountQuery', 'SQL query for counting group members', 'select COUNT(*) from RADONLINE where DNIS=\'%{Called-Station-Id}\'', 'text', '', 50],
       ['SessionLimit', 'Session Limit', '0', 'text', '', 50],
       ['ClassForSessionLimit', 'Radius Class attribute for session limit', undef, 'textn', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
apply port occupancy limits and usage limits for arbitrary groups of users. 
It requires that you are also using an SQL Session Database.
<b>Database sources</b> is the name of the databse source, in the format
<code>dbi:drivername:parameters</code>. The drivername depends on the
perl DBD drivers you have installed, and the parameters depend on the 
DBD driver you are using. <b>Database user names</b> depends on which DBD
driver you are using, but is normally the name of the database username.
<b>Database passwords</b> depends on which DBD
driver you are using, but is normally the password for the database user 
name. <b>SQL query for counting group members</b> specifies an SQL 
query that will be used to count the users currently online according 
to the SQL Session Database. It should return the number of users already
in this group of users. <b>Session Limit</b> is the absolute upper limit to the number of current logins permitted to this group of users. <b>Radius Class attribute for session limit</b> allows you to set up different charging 
bands for different levels of port occupancy in this group of users. 
You can have one or more ClassForSessionLimit lines. If the current 
level of port usage is below a ClassForSessionLimit, then the class 
name will be applied as a Class attribute to that session. Your NAS 
will then tag all accounting records for that session with the Class 
attribute. If your billing system records and uses the Class attribute 
in accounting records, then you could use this to charge differently 
for different levels of port occupancy. Typical values might be 
<code>normal,10</code> and <code>overflow,20</code>',
      },

     'RADIUS' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Host', 'Remote server host name', undef, 'textn', '', 50],
       ['Secret', 'Shared secret', undef, 'text', '', 50],
       ['AuthPort', 'Authentication port', '1645', 'text', '', 50],
       ['AcctPort', 'Accounting port', '1646', 'text', '', 50],
       ['Retries', 'Number of retransmissions', '3', 'text', '', 50],
       ['RetryTimeout', 'Seconds to wait before retransmitting', '5', 'text', '', 50],
       ['StripFromRequest', 'Strip attributes from forwarded request', undef, 'text', '', 50],
       ['AddToRequest', 'Add attributes to forwarded request', undef, 'text', '', 50],
       ['NoForwardAuthentication', 'Don\'t forward authentication requests', 0, 'checkbox', ''],
       ['NoForwardAccounting', 'Don\'t forward accounting requests', 0, 'checkbox', ''],
       ['IgnoreReject', 'Ignore rejections', 0, 'checkbox', ''],
       ['ReplyHook', 'Reply hook', undef, 'textarea', '', 50],
       ['NoReplyHook', 'No reply hook', undef, 'textarea', '', 50],
       ['UseOldAscendPasswords', 'Send old Ascend-compatible password encryption', 0, 'checkbox', ''],
       ['ServerHasBrokenPortNumbers', 'Remote server has broken port numbering', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['AllowInReply', 'Reply Attributes that are permitted to be proxied', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],

       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from and send accouting to another remote Radius server.
You can have one or more <b>Remote server host name</b> entries to
provide fallbacks in the case of no reply. <b>Strip Attributes</b> 
is a comma separated list of Radius attribute names, for 
example <code>Framed-IP-Address,Session-Timeout</code>. 
<b>Add Attributes</b> 
is a comma separated list of Radius attribute=value pairs, for 
example <code>Service-Type=Authenticate-Only,Acct-Authentic=Local</code>. 
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'RADKEY' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Secret', 'Company secret', undef, 'text', '', 50],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from <a href=http://www.open.com.au/radkey>RadKey</a> tokens.
<b>Company secret</b> is the shared secret that is configured into each 
RadKey using the <i>RadKey Token Administrator</i> software.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'RODOPI' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['DBSource', 'Database sources', undef, 'textn', '', 50],
       ['DBUsername', 'Database user names', undef, 'textn', '', 50],
       ['DBAuth', 'Database passwords', undef, 'textn', '', 50],
       ['Timeout', 'SQL access timeout', undef, 'text', '', 50],
       ['FailureBackoffTime', 'Failure backoff time', undef, 'text', '', 50],
       ['AccountingTable', 'Accounting Table name', 'ACCOUNTING', 'text', '', 50],
       ['AuthSelect', 'SQL authentication query', 'select PASSWORD from SUBSCRIBERS where USERNAME=\'%n\'', 'text', '', 50],
       ['EncryptedPassword', 'Password field is encrypted', 0, 'checkbox', ''],
       ['AccountingStartsOnly', 'Store accounting starts only', 0, 'checkbox', ''],
       ['AccountingStopsOnly', 'Store accounting stops only', 0, 'checkbox', ''],
       ['AuthColumnDef', 'Authentication query column definitions', undef, 'textn', '', 50],
       ['AcctColumnDef', 'Accounting column definitions', undef, 'textn', '', 50],
       ['AcctSQLStatement', 'Extra accounting query', undef, 'text', '', 50],
       ['TimeBanking', 'Use time banking', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from the <a href=http://www.rodopi.com>Rodopi</a> 
billing package.
<b>Database sources</b> is the name of the databse source, in the format
<code>dbi:drivername:parameters</code>. The drivername depends on the
perl DBD drivers you have installed, and the parameters depend on the 
DBD driver you are using. <b>Database user names</b> depends on which DBD
driver you are using, but is normally the name of the database username.
<b>Database passwords</b> depends on which DBD
driver you are using, but is normally the password for the database user 
name.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'SQL' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['DBSource', 'Database sources', undef, 'textn', '', 50],
       ['DBUsername', 'Database user names', undef, 'textn', '', 50],
       ['DBAuth', 'Database passwords', undef, 'textn', '', 50],
       ['Timeout', 'SQL access timeout', undef, 'text', '', 50],
       ['FailureBackoffTime', 'Failure backoff time', undef, 'text', '', 50],
       ['AccountingTable', 'Accounting Table name', 'ACCOUNTING', 'text', '', 50],
       ['AuthSelect', 'SQL authentication query', 'select PASSWORD from SUBSCRIBERS where USERNAME=\'%n\'', 'text', '', 50],
       ['EncryptedPassword', 'Password field is encrypted', 0, 'checkbox', ''],
       ['AccountingStartsOnly', 'Store accounting starts only', 0, 'checkbox', ''],
       ['AccountingStopsOnly', 'Store accounting stops only', 0, 'checkbox', ''],
       ['AuthColumnDef', 'Authentication query column definitions', undef, 'textn', '', 50],
       ['AcctColumnDef', 'Accounting column definitions', undef, 'textn', '', 50],
       ['AcctSQLStatement', 'Extra accounting query', undef, 'text', '', 50],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],

       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from almost any SQL database server. Requires DBI and the 
appropriate DBD module for your database from 
<a href=http://www.perl.com/cpan>CPAN</a>.
<b>Database sources</b> is the name of the databse source, in the format
<code>dbi:drivername:parameters</code>. The drivername depends on the
perl DBD drivers you have installed, and the parameters depend on the 
DBD driver you are using. <b>Database user names</b> depends on which DBD
driver you are using, but is normally the name of the database username.
<b>Database passwords</b> depends on which DBD
driver you are using, but is normally the password for the database user 
name.
<b>Accounting Table name</b> is the name of the SQL accoutnign table
in which to insert Radius accounting data.
<b>SQL authentication query</b> is the SQL query that will be sued to get
the password and possibly other attribtues to use to authenticate the user.
By default it only needs to return the password, but you can get other check and reply items if you also use <b>Authentication query column definitions</b> to specify what to do with them.
<b>Accounting column definitions</b> specifies what Radius attributes are
to be stored in which columns in the Accounting Table. Examples might be
<code>ACCTSTATUSTYPE,Acct-Status-Type</code> 
and <code>ACCTINPUTOCTETS,Acct-Input-Octets,integer</code>.
<b>Extra accounting query</b> is an SQL query that will be run before
the usual accounting INSERT.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.
',
      },

     'SYSTEM' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['UseGetspnam', 'Use getspnam() for shadow passwords', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from your host\'s native password authentication system,
such as password file, shadow file, NIS+ or whatever your host
is configured to use for <code>getpwnam()</code> and 
<code>getgrnam()</code>. If your system
uses shadow passwords you may need to select <b>Use getspnam() for shadow passwords</b> and install the Shadows module
(see the reference manual for more details).
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'TACACSPLUS' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Host', 'TACACS+ server host name', 'localhost', 'text', '', 50],
       ['Timeout', 'Timeout (seconds)', 15, 'text', '', 50],
       ['Port', 'Server port', 'tacacs', 'text', '', 50],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from a remote TACACS+ server. Requires the Authen::TacacsPlus module from <a href=http://www.perl.com/cpan>CPAN</a>.

<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.
',
      },

     'TEST' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
to do some simple testing. This module always accepts authentication
requests.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     'UNIX' => 
     {
      'title' => '<AuthBy ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Filename', 'Password file name', '/etc/passwd', 'text', '', 50],
       ['GroupFilename', 'Group file name', '/etc/group', 'text', '', 50],
       ['Match', 'Alternate file parser', undef, 'text', '', 50],
       ['NoCache', 'Dont cache', 0, 'checkbox', ''],
       ['AcceptIfMissing', 'Accept if the user name is not present', 0, 'checkbox', ''],
       ['DefaultSimultaneousUse', 'Simultaneous use limit if no user-specific limit', undef, 'text', '', 50],
       ['DefaultReply', 'Default Reply Attributes if accepted', undef, 'text', '', 50],
       ['AddToReply', 'Reply Attributes if accepted', undef, 'text', '', 50],
       ['StripFromReply', 'Strip these Reply Attributes ', undef, 'text', '', 50],
       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This authentication module allows you to 
authenticate from Unix style passwd and group files.
<b>Default Reply</b>is a comma separated list of attribute=value Radius
attributes that will be replied if there are no other reply attributes
for that user.
<b>Reply Attributes</b> is a comma separated list of attribute=value 
Radius attributes that will be added to every reply.
<b>Strip from reply</b> is a comma separated list of attributes that
will be removed from all replies.',
      },

     );
my %loguidescs = 
    (
     'SQL' => 
     {
      'title' => '<Log ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Trace', 'Trace level', undef, 'menu', '', \%tracelevels],
       ['DBSource', 'Database sources', undef, 'textn', '', 50],
       ['DBUsername', 'Database user names', undef, 'textn', '', 50],
       ['DBAuth', 'Database passwords', undef, 'textn', '', 50],
       ['Timeout', 'SQL access timeout', undef, 'text', '', 50],
       ['FailureBackoffTime', 'SQL failure backoff time', undef, 'text', '', 50],
       ['Table', 'SQL Log table name', 'RADLOG', 'text', '', 50],
       ['LogQuery', 'SQL Insert query', 'insert into $self->{Table} (TIME_STAMP, PRIORITY, MESSAGE) values (%t, $p, $s)', 'text', ''],
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This module records logging information
in an SQL database.
<b>Database sources</b> is the name of the databse source, in the format
<code>dbi:drivername:parameters</code>. The drivername depends on the
perl DBD drivers you have installed, and the parameters depend on the 
DBD driver you are using. <b>Database user names</b> depends on which DBD
driver you are using, but is normally the name of the database username.
<b>Database passwords</b> depends on which DBD
driver you are using, but is normally the password for the database user 
name.',
      },
     'FILE' => 
     {
      'title' => '<Log ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Trace', 'Trace level', undef, 'menu', '', \%tracelevels],
       ['Filename', 'File name', '%L/logfile', 'text', '', 50],
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This module records logging information
to a flat file.',
      },
     'SYSLOG' => 
     {
      'title' => '<Log ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Trace', 'Trace level', undef, 'menu', '', \%tracelevels],
       ['Facility', 'Log to syslog facility name', 'user', 'text', '', 50],
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This module records logging information
to the SYSLOG logging system. <b>Facility</b> specifies which SYSLOG facility
will be used to record the logging information',
      },
     );

my %sessiondatabaseuidescs = 
    (
     'SQL' => 
     {
      'title' => '<SessionDatabase ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['DBSource', 'Database sources', undef, 'textn', '', 50],
       ['DBUsername', 'Database user names', undef, 'textn', '', 50],
       ['DBAuth', 'Database passwords', undef, 'textn', '', 50],
       ['Timeout', 'SQL access timeout', undef, 'text', '', 50],
       ['FailureBackoffTime', 'Failure backoff time', undef, 'text', '', 50],
       ['AddQuery', 'SQL query for adding sessions', "insert into RADONLINE (USERNAME, NASIDENTIFIER, NASPORT, ACCTSESSIONID, TIME_STAMP, FRAMEDIPADDRESS, NASPORTTYPE, SERVICETYPE) values ('%u', '%N', 0%{NAS-Port}, '%{Acct-Session-Id}', %{Timestamp}, '%{Framed-IP-Address}', '%{NAS-Port-Type}', '%{Service-Type}')", 'text', '', 50],
       ['DeleteQuery', 'SQL query for deleting sessions', "delete from RADONLINE where NASIDENTIFIER='%N' and NASPORT=0%{NAS-Port}", 'text', '', 50],
       ['ClearNasQuery', 'SQL query for deleting all sessions for a NAS', "delete from RADONLINE where NASIDENTIFIER='%N'", 'text', '', 50],
       ['CountQuery', 'SQL Query for counting sessions', "select NASIDENTIFIER, NASPORT, ACCTSESSIONID from RADONLINE where USERNAME='%u'", 'text', '', 50],
       ['CountNasSessionsQuery', 'SQL query for counting sessions on a NAS', "select ACCTSESSIONID from RADONLINE where NASIDENTIFIER='%N'", 'text', '', 50],

       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This module records information about
current sessions in an SQL database.
<b>Database sources</b> is the name of the databse source, in the format
<code>dbi:drivername:parameters</code>. The drivername depends on the
perl DBD drivers you have installed, and the parameters depend on the 
DBD driver you are using. <b>Database user names</b> depends on which DBD
driver you are using, but is normally the name of the database username.
<b>Database passwords</b> depends on which DBD
driver you are using, but is normally the password for the database user 
name.',
      },
     'DBM' => 
     {
      'title' => '<SessionDatabase ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['Filename', 'File name', undef, 'text', '', 50],
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
       'documentation' => 'This module records information about
current sessions in a DBM database.',
      },
     'INTERNAL' => 
     {
      'title' => '<SessionDatabase ' . $q->param('_name') . '>',
      'fields' =>
      [
       ['Identifier', 'Identifier', undef, 'text', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
       ['_index', undef, $q->param('_index'), 'hidden'],
       ['_name', undef, $q->param('_name'), 'hidden'],
       ['_item', undef, $q->param('_item'), 'hidden'],
       ],
      },
       'documentation' => 'This module records information about
current sessions in an internal database. Radiator automatically
sets up an INTERNAL session database if no other session databases
are configured',
     );

if ($q->param('_item') eq 'global_directories')
{
    globalDirectoriesPage();
}
elsif ($q->param('_item') eq 'global_daemon')
{
    globalDaemonPage();
}
elsif ($q->param('_item') eq 'global_logging')
{
    globalLoggingPage();
}
elsif ($q->param('_item') eq 'global_ports')
{
    globalPortsPage();
}
elsif ($q->param('_item') eq 'global_rewrites')
{
    globalRewritesPage();
}
elsif ($q->param('_item') eq 'global_variables')
{
    globalVariablesPage();
}
elsif ($q->param('_item') eq 'global_nas')
{
    globalNasPage();
}
elsif ($q->param('_item') eq 'global_showconfig')
{
    globalShowconfigPage();
}
elsif ($q->param('_item') eq 'global_hooks')
{
    globalHooksPage();
}
elsif ($q->param('_item') eq 'SNMPAgent')
{
    snmpAgentPage();
}
elsif ($q->param('_item') eq 'Client')
{
    clientsPage();
}
elsif ($q->param('_item') eq 'AuthBy')
{
    authbyPage();
}
elsif ($q->param('_item') eq 'Realm')
{
    realmsPage();
}
elsif ($q->param('_item') eq 'Handler')
{
    handlersPage();
}
elsif ($q->param('_item') eq 'Log')
{
    logPage();
}
elsif ($q->param('_item') eq 'SessionDatabase')
{
    sessiondatabasePage();
}
else
{
    &mainPage();
}

###############################################################
# Read the Radiator config file and save it as a hash $c
sub readConfig
{
    my ($f, $c) = @_;

    local *CONFIG;
    open(CONFIG, $f) || fatalError("Could not read Radiator config file $f: $!");
    &parse(*CONFIG, $c);
    close(CONFIG);
}

###############################################################
# Save the radiator config to the named file
sub saveConfig
{
    my ($f, $c) = @_;

    my $time = scalar localtime(time);
    local *CONFIG;
    open(CONFIG, ">$f") || fatalError("Could not save Radiator config file $f: $!");
    print CONFIG "# Radiator configuration file.\n# Produced by $myself $time\n#REMOTE_USER: $ENV{REMOTE_USER}, REMOTE_ADDR: $ENV{REMOTE_ADDR}\n\n";
    &dumpConfig(*CONFIG, $c);
    close(CONFIG);
}

###############################################################
#
# config is a ref to a hash into which the parsed data
# is to be put
sub parse
{
    my ($handle, $c) = @_;

    local (*HANDLE) = $handle;
    my $line; # Assemble continued lines
    while (<HANDLE>)
    {
#	print $_; # test
	chomp;

	# Strip leading and trailing white space
	s/^\s*//;
	s/\s*$//;

	# Ignore blank lines and lines beginning with hash
	next if $_ eq '' || /^#/;

	$line .= $_;
	next if ($line =~ s/\\$//); # Line continuation

	# Look for </Objectname> to end the object definition
	last if ($line =~ /^<\/([^>]*)>/);

	if ($line =~ /^<\s*(\S*)\s*(.*)>/)
	{
	    my ($type, $key) = ($1, $2);

	    # Start of an object definition
	    # Make a new hash to store it in
	    my $hash = {};
	    parse($handle, $hash);

	    # Special cases for AuthBy. All nested AuthBys get
	    # flattened up to the global level, and they 
	    # get a default Identifier
	    if ($type eq 'AuthBy')
	    {
		push(@{$$hash{'Identifier'}}, "ID_" . $ids++)
		    unless exists $$hash{'Identifier'};
		my $identifier = getLastEntry($hash, 'Identifier');
		# Save it in the top level
		push(@{$globalconfig{$type}}, [$key, $hash]);
		# Save a reference to it at this level
		push(@{$$c{AuthBy}}, $identifier)
		    unless $c == \%globalconfig;
	    }
	    else
	    {
		push(@{$$c{$type}}, [$key, $hash]);
	    }
	}
	elsif ($line =~ /(\S*)\s*(.*)/)
	{
	    # Keyword value
	    # Every named parameter is stored as an array of values
	    # this lerts us deal with multiple identically nameed
	    # parameters
	    push(@{$$c{$1}}, $2);
	}
	$line = '';
    }	
}

###############################################################
# Recursive routine to print the contents of a
# a configuration hash
# config is a reference to a hash of configured items
# REVISIT: perhaps should dump the simple params first, and the
# subobjects second?
sub dumpConfig
{
    my ($handle, $c, $level) = @_;

    my ($key, $entry);
    # First print the simple paramters
    foreach $key (sort keys %$c)
    {
	foreach $entry (@{$$c{$key}})
	{
	    if ((ref $entry) ne 'ARRAY')
	    {
		# Simple parameter
		print $handle '  ' x $level, "$key $entry\n";
	    }
	}
    }
    # Then the subobjects
    foreach $key (sort keys %$c)
    {
	foreach $entry (@{$$c{$key}})
	{
	    if ((ref $entry) eq 'ARRAY')
	    {
		# Its an array of subobjects
		my ($name, $hash) = @$entry;
		print $handle '  ' x $level, "\n<$key $name>\n";
		&dumpConfig($handle, $hash, $level+1);
		print $handle '  ' x $level, "</$key>\n";

	    }
	}
    }
}

####################################################################
# Get the value of the last entry named from the given hash
# If there is no value, use the default
sub getLastEntry
{
    my ($c, $name, $default) = @_;
    my $ret;
    
    $ret = ${$$c{$name}}[scalar @{$$c{$name}} - 1];
    $ret = $default unless defined $ret;
    return $ret;
}

####################################################################
# Set a single entry value. All existing entries with the same
# name are deleted
sub setEntry
{
    my ($c, $name, $value) = @_;
    $$c{$name} = [$value];
}

####################################################################
# Add an entry to the end of the named list

sub addEntry
{
    my ($c, $name, $entry) = @_;

    push(@{$$c{$name}}, $entry);
}

####################################################################
# Set a single entry value. All existing entries with the same
# name are deleted.
# $value is a ref to an array of values
sub setEntries
{
    my ($c, $name, $value) = @_;
    $$c{$name} = $value;
}

####################################################################
# Set a single entry value. All existing entries with the same
# name are deleted
sub deleteEntries
{
    my ($c, $name) = @_;
    delete $$c{$name};
}

####################################################################
# Get a set of named entries
sub getEntries
{
    my ($c, $name) = @_;

    return @{$$c{$name}};
}

####################################################################
# Basic fatal error handler
# Overrides the one on Util.pm
sub main::fatalError
{
    my ($msg) = @_;

    print $q->header;
    print <<_END_OF_CONTENT_;
<html><head><title>Error</title></head>
<body bgcolor=white><h1>Error</h1>
<strong>A serious error has occurred:</strong>
<p>$msg
<hr>
Please report problems with this system to
<a href="mailto:$adminAddress">
$adminAddress</a>
</body></html>
_END_OF_CONTENT_
    exit 1;
}

###############################################################
# Build a list of hotlinks for all the items in the global
# config file identified $name
# BUild a hot link for each existing items, and a New... button
sub getTypeEntryList
{
    my ($type, $extras) = @_;

    my $ret;
    for ($i = 0; $i < @{$globalconfig{$type}}; $i++)
    {
	my ($name, $hash) = @{${$globalconfig{$type}}[$i]};
        my $id = getLastEntry($hash, 'Identifier');
        my $escapedname = $name;
        $escapedname =~ tr/ /+/; # spaces to pluses
	$ret .= "<a href=$myself?_item=$type&_action=Edit&_name=$escapedname&_index=$i>$name&nbsp;$id</a><br>\n";
    }
    $ret .= "<form>"
    . $q->hidden('_item', $type)
    . $q->submit(-name => '_action', -value => 'New...')
    . "&nbsp" . $extras
    . '</form>';

    return $ret;
}

###############################################################
#
sub mainPage
{
    my ($i, $clients, $authenticators,
	$realms, $handlers, $loggers, $sessiondatabases);

    $clients = getTypeEntryList('Client');

    my @options = sort keys %authbyuidescs;
    $authenticators = getTypeEntryList
	('AuthBy', 
	 $q->popup_menu('_name', \@options));

    $realms = getTypeEntryList('Realm');
    $handlers = getTypeEntryList('Handler');

    @options = sort keys %loguidescs;
    $loggers = getTypeEntryList
	('Log', 
	 $q->popup_menu('_name', \@options));

    @options = sort keys %sessiondatabaseuidescs;
    $sessiondatabases = getTypeEntryList
	('SessionDatabase', 
	 $q->popup_menu('_name', \@options));

    my $contents .= "<h3>Global Configuration</h3>
<table width=100%>
<tr>
<td><a href=$myself?_item=global_directories>Directories</a></td>
<td><a href=$myself?_item=global_daemon>Daemon</a></td>
<td><a href=$myself?_item=global_rewrites>Global Username Rewrites</a></td>
<td><a href=$myself?_item=global_logging>Logging</a></td>
<td><a href=$myself?_item=global_ports>Ports</a></td>
</tr><tr>
<td><a href=$myself?_item=global_variables>Variables</a></td>
<td><a href=$myself?_item=global_nas>NAS communications</a></td>
<td><a href=$myself?_item=global_hooks>Global Hooks</a></td>
<td><a href=$myself?_item=SNMPAgent>SNMP Agent</a></td>
<td><a href=$myself?_item=global_showconfig>Show Current Configuration File</a></td>
</tr></table>
<hr>
<h3>Clients</h3>
You must define a Client for each NAS that you wish to serve.<br>
$clients
<hr>
<h3>Authenticators</h3>
You must define an Authenticator for each authentication method
you need to use.<br>
$authenticators
<hr>
<h3>Realms</h3>
You must define a Realm for each Radius realm that you need to serve. 
DEFAULT is a fallback Realm.<br>
$realms
<hr>
<h3>Handlers</h3>
You only need to define Handlers if you cant do exactly what you need 
with Realms.<br>
$handlers
<hr>
<h3>Loggers</h3>
$loggers
<hr>
<h3>Session Databases</h3>
$sessiondatabases
<p>
These pages allow you to create and maintian your Radiator 
configuration file. In order to get started, you should define
your Directories and a Client for each NAS that you have. Then
define an Authenticator for each authentication method you need to
use, and finally create a Realm for each Radius realm you have to 
handle, taking care to name the right Authenticator to use to 
authenticate that realm. Most other features are advanced, so consult 
the Reference manual for more details.
";

    pageTemplate($contents);
}

sub pageTemplate
{
    my ($contents) = @_;
    print $q->header;
    print <<EOF;
<html>
<head>
<title>Radiator configuration</title>
$refresh
</head>
$localheader
$toolBar
<hr>
$contents
$localfooter</html>
EOF
}

###############################################################
sub globalDirectoriesPage
{
    my %uidesc = 
	(
	 'title' => 'Directories',
	 'fields' =>
	 [
	  ['DbDir', 'Database directory (%D)', '/usr/local/etc/raddb', 'text', '', 50],
	  ['DictionaryFile', 'Dictionary File', '%D/dictionary', 'text', '', 50],
	  ['_item', undef, 'global_directories', 'hidden'],
	  ],
       'documentation' => 'This page allows you to configure the main
directories and files that Radiator needs.',
	 );
    &editor(\%globalconfig, \%uidesc);
}

###############################################################
sub globalPortsPage
{
    my %uidesc = 
	(
	 'title' => 'Ports',
	 'fields' =>
	 [
	  ['AuthPort', 'Authentication port', '1645', 'text', '', 50],
	  ['AcctPort', 'Accounting port', '1646', 'text', '', 50],
	  ['SocketQueueLength', 'Socket Queue buffer length', undef, 'text', '', 50],
	  ['_item', undef, 'global_ports', 'hidden'],
	  ],
       'documentation' => 'This page allows you to configure details about
the UDP ports that Radiator uses to receive requests from your NASs',
	 );
    &editor(\%globalconfig, \%uidesc);
}

###############################################################
sub globalRewritesPage
{
    my %uidesc = 
	(
	 'title' => 'Global Username Rewrites',
	 'fields' =>
	 [
	  ['RewriteUsername', 'User-Name rewriting rules', undef, 'textn', '', 50],
	  ['_item', undef, 'global_rewrites', 'hidden'],
	  ],
       'documentation' => 'This page allows you to set up username
rewriting for all requests. User names in every incoming request will be rewritten using theses rules, applied in the order given. 
A rewriting rule is a perl substitution
pattern, such as <br><code>tr/[a-z]/[A-Z]/</code><br>to translate all lowercase
to uppercase letters, or <br><code>s/^([^@]+).*/$1/</code> <br>to strip
off realm names.',
	 );
    &editor(\%globalconfig, \%uidesc);
}

###############################################################
sub globalVariablesPage
{
    my %uidesc = 
	(
	 'title' => 'Global Variables',
	 'fields' =>
	 [
	  ['DefineGlobalVar', 'Define Global Variables', undef, 'textn', '', 50],
	  ['_item', undef, 'global_variables', 'hidden'],
	  ],
       'documentation' => 'This page allows you to configure your
own site-specific global 
variables. Global variable definitions consist of a variable name and a 
value, such as<br>
myvariable xyzzy<br>
myothervariable 1234<br>
Global Variables can be used anywhere that special
characters can be used with something like: 
<code>%{GlobalVar:myvariable}</code>, which
would be replaced with the value of <code>myvariable</code>.',
	 );
    &editor(\%globalconfig, \%uidesc);
}

###############################################################
sub globalNasPage
{
    my %uidesc = 
	(
	 'title' => 'Global NAS Configuration',
	 'fields' =>
	 [
	  ['FingerProg', 'Full path to finger program', undef, 'text', '', 50],
	  ['SnmpgetProg', 'Full path to snmpget program', '/usr/bin/snmpget', 'text', '', 50],
	  ['PmwhoProg', 'Full path to pmwho program', '/usr/local/sbin/pmwho', 'text', '', 50],
	  ['LivingstonMIB', 'Livingston SNMP MIB', undef, 'text', '', 50],
	  ['LivingstonOffs', 'Livingston port hole offset', 29, 'text', '', 50],
	  ['LivingstonHole', 'Livingston port hole size', 2, 'text', '', 50],


	  ['_item', undef, 'global_nas', 'hidden'],
	  ],
       'documentation' => 'This page allows you to configure information 
about how to communicate with your NASs for strong simultaneous-use
checking. They are only required if you use Simultaneous-Use check items, and
also specify NAS Type in your <Client>. Radiator will use these parameters
to confirm port occupancy when usage limits are exceeded.
',
	 );
    &editor(\%globalconfig, \%uidesc);
}

sub globalShowconfigPage
{
    my $contents;

    open(FILE, $filename) || 
	fatalError("Could not open Radiator config file $f: $!");
    $contents = '<pre>';
    while (<FILE>)
    {
	$contents .= $q->escapeHTML($_);
    }
    $contents .= '</pre>';
    pageTemplate($contents);
}

###############################################################
sub globalHooksPage
{
    my %uidesc = 
	(
	 'title' => 'Global Hooks',
	 'fields' =>
	 [
	  ['StartupHook', 'Startup Hook', undef, 'textarea', '', 50, 3],
	  ['PreClientHook', 'Pre-Client Hook', undef, 'textarea', '', 50, 3],

	  ['_item', undef, 'global_hooks', 'hidden'],
	  ],
       'documentation' => 'This page allows you to set up perl code that 
will be run for you under cetain circumstances. 
<b>Startup Hook</b> will be run when Radiator starts or restarts.
<b>Pre-Client Hook</b> will be run for each Radius request before being processed by its Client clause.',
	 );
    &editor(\%globalconfig, \%uidesc);
}

###############################################################
sub globalDaemonPage
{
    my %uidesc = 
	(
	 'title' => 'Daemon settings',
	 'fields' =>
	 [
	  ['Foreground', 'Run in foreground', 1, 'checkbox', '', 50],
	  ['PidFile', 'Daemon PID file', '%L/radiusd.pid', 'text', '', 50],
	  ['_item', undef, 'global_daemon', 'hidden'],
	  ],
       'documentation' => 'This page allows you to configure Radiator\'s
daemon behaviour. Becoming a daemon is not supported on Windows platforms.',
	 );
    &editor(\%globalconfig, \%uidesc);
}

###############################################################
sub globalLoggingPage
{
    my %uidesc = 
	(
	 'title' => 'Logging',
	 'fields' =>
	 [
	  ['LogDir', 'Log directory (%L)', '/var/log/radius', 'text', '', 50],
	  ['LogFile', 'Log file name', '%L/logfile', 'text', '', 50],
	  ['Trace', 'Logging level', 2, 'menu',  '', \%tracelevels,
	   ],
	  ['LogStdout', 'Log to stdout too', 1, 'checkbox', ''],
	  ['_item', undef, 'global_logging', 'hidden'],
	  ],
       'documentation' => 'This page allows you to configure logging 
behaviour',
	 );
    &editor(\%globalconfig, \%uidesc);
}

###############################################################
sub snmpAgentPage
{
    # First find the last SNMPAgent
    my ($ref, $type, $hash);
    $ref = getLastEntry(\%globalconfig, 'SNMPAgent');
    ($type, $hash) = @$ref if $ref;

    my %uidesc = 
	(
	 'title' => "<SNMPAgent>",
	 'fields' =>
	 [
	  ['Community', 'Community name for authentication', 'public', 'text', '', 50],
	  ['Port', 'Port to listen on', '161', 'text', '', 50],
	  ['BindAddress', 'Alternative address to listen on', undef, 'text', '', 50],
	  ['_item', undef, 'SNMPAgent', 'hidden'],
	  ],
       'documentation' => 'The page allows you to add or configure an 
SNMPAgent. If you configure an SNMP Agent, Radiator will respond to SNMP
requests using the Draft IETF Radius Server MIB',
	 );
    &editor($hash, \%uidesc);
}

###############################################################
sub clientsPage
{
    # First find the Client that was named
    # _index is the index into the Client array
    my ($ref, $type, $hash);
    $q->param('_index', scalar @{$globalconfig{Client}}) 
	unless defined $q->param('_index');
    $ref = ${$globalconfig{Client}}[$q->param('_index')];
    ($type, $hash) = @$ref if $ref;

    my %uidesc = 
	(
	 'title' => "<Client $type>",
	 'fields' =>
	 [
	  ['_name', 'IP Address or DNS name', undef, 'key', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
	  ['Secret', 'Shared Secret', undef, 'text', '', 50],
	  ['NasType', 'NAS Type', 'unknown', 'menu',  '',
	   ['unknown', 'Livingston', 'Portslave', 'PortslaveLinux', 'Cisco', 'Ascend', 'Shiva', 'TotalControl', 'Computone', 'Bay', 'Xyplex', 'AscendSNMP', 'TotalControlSNMP', 'Bay5399SNMP', 'Bay8000SNMP', 'Bay4000SNMP', 'BayFinger', 'Hiper', 'Tigris', 'TigrisNew', 'TigrisOld', 'NortelCVX1800', 'Portmaster4', 'Ping', 'ignore', 'other']],
	  ['DupInterval', 'Duplicate detection interval', 2, 'text', '', 50],
	  ['DefaultRealm', 'Default Realm', undef, 'text', '', 50],
	  ['IdenticalClients', 'Other Identical Clients', undef, 'textn', '', 50, 3],
	  ['IgnoreAcctSignature', 'Ignore Accounting Signature', undef, 'checkbox', ''],
	  ['NoIgnoreDuplicates', 'Dont ignore duplicates of', undef, 'text', '', 50],

	  ['_item', undef, 'Client', 'hidden'],
	  ['_index', undef, $q->param('_index'), 'hidden'],
	  ],
       'documentation' => 'This page defines one or more Radius clients 
(NASs)that Radiator will respond to. 
Requests from clients that are not configured into Radiator with a Client
will be ignored. If the name is given as <code>DEFAULT</code>, then
this definition will be used to handle request from all NASs that do
not have their own Client.<br>
<b>Shared Secret</b> must be specified, and must agree with the shared
secret configured into the NAS.
<b>NasType</b> is only required if <i>strong</i> simultaneous-use 
protection is required. It specifies what type of NAS this is.
<b>Ignore Accounting Signature</b> may be needed for some old model
NASs that do not send Radius compliant authenticaiton signatures in 
accounting requests.
<b>Duplicate detection interval</b> is the number of seconds between
2 requests with the same indentifier that will be regared as retransmissions.
retransmitted requests will be ignored.
<b>Default Realm</b> will be appended to any user name that does not have a
realm. For example if Default Realm is set to <code>my.com</code>, a user
who tries to log in as fred will be changed to fred@my.com.
<b>Other Identical Clients</b> is a comma or space separated
list of DNS names or addrsses of
other NASs with identical tpes and secrets. If all your NASs are identical,
it is sometimes convenient to use this instread of having a &lt;Client&gt; 
for every NAS.
',
	 );
    &editor($hash, \%uidesc);
}

###############################################################
# Generate a list of all the available AuthBy Identifiers
sub getAuthByIdentifiersList
{
    my @identifiers = (''); # List of available AuthBy identifier names
    my $i;
    for ($i = 0; $i < @{$globalconfig{AuthBy}}; $i++)
    {
	my ($name, $hash) = @{${$globalconfig{AuthBy}}[$i]};
        push(@identifiers, getLastEntry($hash, 'Identifier'));
    }
    return @identifiers;
}

###############################################################
sub realmsPage
{
    # First find the realm that was named
    # _index is the index into the Client array
    my ($ref, $type, $hash);
    $q->param('_index', scalar @{$globalconfig{Realm}}) 
	unless defined $q->param('_index');
    $ref = ${$globalconfig{Realm}}[$q->param('_index')];
    ($type, $hash) = @$ref if $ref;
    
    my @identifiers = getAuthByIdentifiersList();

    my @sessiondatabases = (''); # List of available Session Database identifier names
    my $i;
    for ($i = 0; $i < @{$globalconfig{SessionDatabase}}; $i++)
    {
	my ($name, $hash) = @{${$globalconfig{SessionDatabase}}[$i]};
	push(@sessiondatabases, getLastEntry($hash, 'Identifier'));
    }

    my %uidesc = 
	(
	 'title' => "<Realm $type>",
	 'fields' =>
	 [
	  ['_name', 'Realm name', undef, 'key', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
	  ['AuthByPolicy', 'Authentication policy', 'ContinueWhileIgnore', 'menu',  '', \@authbypolicies],
	  ['AuthBy', 'Authentication methods', undef, 'menun', '', \@identifiers],
	  ['_item', undef, 'Realm', 'hidden'],
	  ['MaxSessions', 'Max number of sessions', undef, 'text', '', 50],
	  ['RewriteUsername', 'User-Name rewriting rules', undef, 'textn', '', 50],
	  ['AcctLogFileName', 'Accounting log file name', undef, 'textn', '', 50],
	  ['WtmpFileName', 'Wtmp log file name', undef, 'text', '', 50],
	  ['PasswordLogFileName', 'Password log file name', undef, 'text', '', 50],
	  ['ExcludeFromPasswordLog', 'Exclude from password log file (exact)', undef, 'text', '', 50],
	  ['ExcludeFromPasswordLog', 'Exclude from password log file (regex)', undef, 'text', '', 50],
	  
	  ['RejectHasReason', 'Rejection reasons in reject messages', undef, 'checkbox', '', 50],
	  ['AccountingHandled', 'Always accept accounting', undef, 'checkbox', '', 50],
	  ['PreProcessingHook', 'Pre-Processing Hook', undef, 'textarea', '', 50, 3],
	  ['PreAuthHook', 'Pre-Authentication Hook', undef, 'textarea', '', 50, 3],
	  ['PostAuthHook', 'Post-Authentication Hook', undef, 'textarea', '', 50, 3],
	  
	  ['SessionDatabase', 'Session Database', undef, 'menu', '', \@sessiondatabases],
	  ['_index', undef, $q->param('_index'), 'hidden'],
	  ],
       'documentation' => 'This page defines how to handle
all requests from users with a given realm. If the name is blank, it
wil be used for all requests with <i?no</i> realm.
If the name <code>DEFAULT</code>
is specified, it will be used for all requests that do not have a specific
matching Realm. Radiator will look for matching Realms before Handlers.<br>
Realm will
authenticate from each of the modules identified by 
<b>Authentication methods</b> until the <b>Authentication policy</b>
is satisfied. The <b>Authentication methods</b> menu specifies the 
Identifier of AuthBy modules that you have previously configured.<b></b>
<b>Max number of sessions</b> provides additional limits on 
the number of sessions permitted
by each user in this realm. The <i>minimum</i> if this and any per user 
Simultaneous-Use will apply. For a default Simultaneous-Use, use
<b>Default Simultaneous Use</b> in an AuthBy module.
<b>User-Name rewriting rules</b> are per substitution patterns that will
be applied to the user name in order before the Authentication Methods are
called.
<b>Accounting log file name</b> is the name of a file to log acconting
data in Livingston standard detail file format.
<b>Wtmp log file name</b> is the name of a Unix wtmp file to record logins.
<b>Password log file name</b> is the name of a file in which to
record all login attemts, including the submitted password.
<b>Exclude from password log...</b> are names that will not be recorded in
the Password log file, for security reasons.
The <b>Hook</b>s are perl functions that will be run for each request 
at different times dring processing.
<b>Session Database</b> is the Identifier of a Session Databse in which
to record sessions for this realm.
',
	 );
    &editor($hash, \%uidesc);
}

###############################################################
sub handlersPage
{
    # First find the Handlers that was named
    # _index is the index into the Client array
    my ($ref, $type, $hash);
    $q->param('_index', scalar @{$globalconfig{Handler}}) 
	unless defined $q->param('_index');
    $ref = ${$globalconfig{Handler}}[$q->param('_index')];
    ($type, $hash) = @$ref if $ref;
    
    my @identifiers = getAuthByIdentifiersList();

    my @sessiondatabases = (''); # List of available Session Database identifier names
    my $i;
    for ($i = 0; $i < @{$globalconfig{SessionDatabase}}; $i++)
    {
	my ($name, $hash) = @{${$globalconfig{SessionDatabase}}[$i]};
	push(@sessiondatabases, getLastEntry($hash, 'Identifier'));
    }

    my %uidesc = 
	(
	 'title' => "<Handler $type>",
	 'fields' =>
	 [
	  ['_name', 'Check conditions', undef, 'key', '', 50],
       ['Description', 'Brief description of what this is used for', undef, 'text', '', 50],       
	  ['AuthByPolicy', 'Authentication policy', 'ContinueWhileIgnore', 'menu',  '', \@authbypolicies],
	  ['AuthBy', 'Authentication methods', undef, 'menun', '', \@identifiers],
	  ['_item', undef, 'Realm', 'hidden'],
	  ['MaxSessions', 'Max number of sessions', undef, 'text', '', 50],
	  ['RewriteUsername', 'User-Name rewriting rules', undef, 'textn', '', 50],
	  ['AcctLogFileName', 'Accounting log file name', undef, 'textn', '', 50],
	  ['WtmpFileName', 'Wtmp log file name', undef, 'text', '', 50],
	  ['PasswordLogFileName', 'Password log file name', undef, 'text', '', 50],
	  ['ExcludeFromPasswordLog', 'Exclude from password log file (exact)', undef, 'text', '', 50],
	  ['ExcludeFromPasswordLog', 'Exclude from password log file (regex)', undef, 'text', '', 50],
	  
	  ['RejectHasReason', 'Rejection reasons in reject messages', undef, 'checkbox', '', 50],
	  ['AccountingHandled', 'Always accept accounting', undef, 'checkbox', '', 50],
	  ['PreProcessingHook', 'Pre-Processing Hook', undef, 'textarea', '', 50, 3],
	  ['PreAuthHook', 'Pre-Authentication Hook', undef, 'textarea', '', 50, 3],
	  ['PostAuthHook', 'Post-Authentication Hook', undef, 'textarea', '', 50, 3],
	  
	  ['SessionDatabase', 'Session Database', undef, 'menu', '', \@sessiondatabases],
	  ['_index', undef, $q->param('_index'), 'hidden'],
	  ],
       'documentation' => 'This page defines how to handle
all requests depending on certain attribtues in the request.
<b>Check conditions</b> is a list of attribute=value pairs that must match
before this Handler will be used. For example, if Check conditions was set to
<code>Called-Station-Id=1234</code>, this handler would be used for all
requests with a Called-Station-Id of 1234. Multiple check conditions 
can be speecified, separted by commas, and regular expressions are 
also supported. If no Check conditions are specified, the Handler will
always be used. Handlers are considered in the order in which they are
defined.<br>
Handler will
authenticate from each of the modules identified by 
<b>Authentication methods</b> until the <b>Authentication policy</b>
is satisfied. The <b>Authentication methods</b> menu specifies the 
Identifier of AuthBy modules that you have previously configured.<b></b>
<b>Max number of sessions</b> provides additional limits on 
the number of sessions permitted
by each user in this realm. The <i>minimum</i> if this and any per user 
Simultaneous-Use will apply. For a default Simultaneous-Use, use
<b>Default Simultaneous Use</b> in an AuthBy module.
<b>User-Name rewriting rules</b> are per substitution patterns that will
be applied to the user name in order before the Authentication Methods are
called.
<b>Accounting log file name</b> is the name of a file to log acconting
data in Livingston standard detail file format.
<b>Wtmp log file name</b> is the name of a Unix wtmp file to record logins.
<b>Password log file name</b> is the name of a file in which to
record all login attemts, including the submitted password.
<b>Exclude from password log...</b> are names that will not be recorded in
the Password log file, for security reasons.
The <b>Hook</b>s are perl functions that will be run for each request 
at different times dring processing.
<b>Session Database</b> is the Identifier of a Session Databse in which
to record sessions for this realm.',
	 );
    &editor($hash, \%uidesc);
}

###############################################################
sub authbyPage
{
    # First find the AuthBy that was named
    # _index is the index into the AuthBy array
    my ($ref, $type, $hash);
    $q->param('_index', scalar @{$globalconfig{AuthBy}}) 
	unless defined $q->param('_index');
    $ref = ${$globalconfig{AuthBy}}[$q->param('_index')];
    ($type, $hash) = @$ref if $ref;

    &editor($hash, $authbyuidescs{$q->param('_name')});
}

###############################################################
sub logPage
{
    # First find the Log that was named
    # _index is the index into the AuthBy array
    my ($ref, $type, $hash);
    $q->param('_index', scalar @{$globalconfig{Log}}) 
	unless defined $q->param('_index');
    $ref = ${$globalconfig{Log}}[$q->param('_index')];
    ($type, $hash) = @$ref if $ref;

    &editor($hash, $loguidescs{$q->param('_name')});
}

###############################################################
sub sessiondatabasePage
{
    # First find the Log that was named
    # _index is the index into the AuthBy array
    my ($ref, $type, $hash);
    $q->param('_index', scalar @{$globalconfig{SessionDatabase}}) 
	unless defined $q->param('_index');
    $ref = ${$globalconfig{SessionDatabase}}[$q->param('_index')];
    ($type, $hash) = @$ref if $ref;

    &editor($hash, $sessiondatabaseuidescs{$q->param('_name')});
}

###############################################################
# Display and manage a HTML editing form
sub editor
{
    my ($config, $desc) = @_;
    my ($buttons, $title);

    my ($table, $field);
    if ($q->param('_action') eq 'Add')
    {
	# Create the new empty object
	$config = {};
	my $name = $q->param('_name');
	$name = "" unless defined $name;
	addEntry(\%globalconfig, $q->param('_item'), [$name, $config]);
    }

    if ($q->param('_action') eq 'Update' || $q->param('_action') eq 'Add')
    {
	# Update fields according the ui description
	foreach $field (@{$desc->{fields}})
	{
	    if ($$field[3] eq 'text')
	    {
		# Editable text field
		my $value = $q->param($$field[0]);
		if ($value ne '')
		{
		    setEntry($config, $$field[0], $q->param($$field[0]));
		}
		else
		{
		    deleteEntries($config, $$field[0]);
		}
	    }
	    elsif ($$field[3] eq 'textn')
	    {
		# Multiple editable text field
		my @values = $q->param($$field[0]);
		# Remove empty ones
		@values = grep { $_ ne '' } @values;
		setEntries($config, $$field[0], \@values);
	    }
	    if ($$field[3] eq 'textarea')
	    {
		# multiline text field, make sure all
		# lines are escaped
		my $text = $q->param($$field[0]);
		$text =~ s/\015/\\/g;
		if ($text ne '')
		{
		    setEntry($config, $$field[0], $text);
		}
		else
		{
		    deleteEntries($config, $$field[0]);
		}
	    }
	    elsif ($$field[3] eq 'checkbox')
	    {
		# Make a single entry with no text
		if ($q->param($$field[0]) eq 'on')
		{
		    setEntry($config, $$field[0], undef);
		}
		else
		{
		    deleteEntries($config, $$field[0]);
		}
	    }
	    elsif ($$field[3] eq 'menu')
	    {
		setEntry($config, $$field[0], $q->param($$field[0]));
	    }
	    elsif ($$field[3] eq 'menun')
	    {
		# Multiple menu field
		my @values = $q->param($$field[0]);
		# Remove empty ones
		@values = grep { $_ ne '' } @values;
		setEntries($config, $$field[0], \@values);
	    }
	}
	&saveConfig($filename, \%globalconfig);
    }


    # Now build the resulting page
    foreach $field (@{$desc->{fields}})
    {
	# $field is a ref to 
	# fieldname, prompt, default, type, size, etc

	my ($helpLink, $value, $input);
	$helpLink = "<a href=$userHelpDoc#$$field[4]><font size=-2>help</font></a>"
	    if $$field[4] ne '';

	# Now build the output display
	if ($$field[3] eq 'key')
	{
	    # The key for this record, either an Editable text field
	    # or a fixed label
	    my $name = $q->param('_name');
	    if (defined $name)
	    {
		
		$input = $name	. $q->hidden(-name => $$field[0],
					     -value => $q->param($$field[0]))
;
	    }
	    else
	    {
		$input = $q->textfield(-name => $$field[0],
				       -value => '',
				       -size => $$field[5]);
	    }
	    $table .= "<tr><th $tha><font $thf>$$field[1]</font></th><td>$input</td><td>$helpLink</td>\n";
	}
	elsif ($$field[3] eq 'text')
	{
	    # Editable text field
	    $value = getLastEntry($config, $$field[0], $$field[2]);
	    $input = $q->textfield(-name => $$field[0],
				   -value => $value,
				   -size => $$field[5]);
	    $table .= "<tr><th $tha><font $thf>$$field[1]</font></th><td>$input</td><td>$helpLink</td>\n";
	}
	elsif ($$field[3] eq 'textn')
	{
	    # Multiple Editable text field
	    @values = getEntries($config, $$field[0]);
	    my ($value, $i, $inputfields);
	    foreach $value (@values)
	    {
		$inputfields .= $q->textfield(-name => $$field[0],
				       -value => $value,
				       -override => 1,
				       -size => $$field[5]) . '<br>';

	    }
	    # Add room for a few more
	    
	    for ($i = 0; $i < 1; $i++)
	    {
		$inputfields .= $q->textfield(-name => $$field[0],
					  -value => '',
					  -override => 1,
					  -size => $$field[5]);
	    }
	    $table .= "<tr><th $tha><font $thf>$$field[1]</font></th><td>$inputfields</td><td>$helpLink</td>\n";

	}
	if ($$field[3] eq 'textarea')
	{
	    # Editable text field
	    $value = getLastEntry($config, $$field[0], $$field[2]);
	    $input = $q->textarea(-name => $$field[0],
				   -value => $value,
				   -cols => $$field[5],
				  -rows => $$field[6]);
	    $table .= "<tr><th $tha><font $thf>$$field[1]</font></th><td>$input</td><td>$helpLink</td>\n";
	}
	elsif ($$field[3] eq 'checkbox')
	{
	    # If there are any entries for thisparam, then
	    # it is selected
	    $input = $q->checkbox(-name => $$field[0],
				  -label => '',
				  -checked => $config && exists $$config{$$field[0]},
				  );
	    $table .= "<tr><th $tha><font $thf>$$field[1]</font></th><td>$input</td><td>$helpLink</td>\n";
	}
	elsif ($$field[3] eq 'menu')
	{
	    $value = getLastEntry($config, $$field[0], $$field[2]);
	    my (@entries, $labels);
	    # The menu can be defines either as an array of names
	    # or a hash of integer->name
	    if (ref $$field[5] eq 'HASH')
	    {
		@entries = sort keys %{$$field[5]};
		$labels = $$field[5];
	    }
	    elsif (ref $$field[5] eq 'ARRAY')
	    {
		@entries = @{$$field[5]};
		$labels = undef;
	    }
	    my $input = $q->popup_menu($$field[0], \@entries, $value, $labels);
	    $table .= "<tr><th $tha><font $thf>$$field[1]</font></th><td>$input</td><td>$helpLink</td>\n";

	}
	elsif ($$field[3] eq 'menun')
	{
	    # Multiple selection menus
	    @entries = getEntries($config, $$field[0]);

	    # The menu can be defines either as an array of names
	    # or a hash of integer->name
	    my (@values, $labels);
	    if (ref $$field[5] eq 'HASH')
	    {
		@values = sort keys %{$$field[5]};
		$labels = $$field[5];
	    }
	    elsif (ref $$field[5] eq 'ARRAY')
	    {
		@values = @{$$field[5]};
		$labels = undef;
	    }

	    my ($value, $i, $inputfields);
	    foreach $value (@entries)
	    {
		$inputfields .= $q->popup_menu($$field[0], 
					      \@values, 
					      $value, 
					      $labels, 1);
	    }
	    # Add room for a few more
	    
	    for ($i = 0; $i < 1; $i++)
	    {
		$inputfields .= $q->popup_menu($$field[0], 
					      \@values, 
					      undef, 
					       $labels, 1);
	    }
	    $table .= "<tr><th $tha><font $thf>$$field[1]</font></th><td>$inputfields</td><td>$helpLink</td>\n";

	}
	elsif ($$field[3] eq 'hidden')
	{
	    $table .= $q->hidden(-name => $$field[0],
				 -value => $q->param($$field[0]));
	}

    }
    if ($config)
    {
	$buttons = "<input type=submit name=_action value='Update'>";
    }
    else
    {
	$buttons = "<input type=submit name=_action value='Add'>";
    }
    $title = $q->escapeHTML($desc->{title});
    $message .= $desc->{documentation};

    print $q->header;
    print <<_END_OF_CONTENT_;
<html>
<head>
<title>Radiator Configuration: $title</title>
</head>
$localheader
$toolBar
<hr>
<h1>$title</h1>
$message
<form method=post>
<table cellspacing=1 cellpadding=0>
$table
<tr><td></td><td>$buttons</td></tr>
<tr><td></td><td>$links</td></tr>
</table>
</form>

$localfooter
</body>
</html>

_END_OF_CONTENT_
}
