#!/usr/local/bin/perl
# radlog.cgi:  Uses html's meta tag to view changes to
# /radius/log/logfile
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime();
$mon++;
$yy = `date '+20%y'`;
$latestrun = "$hour:$min:$sec  $mon/$mday/$yy";

# You may need to change this to match the name of your log file
$logfile =`date '+/radius/log/logfile-20%y-%m-%d'`;

$errors= `tail -25 $logfile`;

print <<EOT;
Content-type: text/html

<html><head>
<meta http-equiv="refresh" Content="10,url=radlog.cgi">
<title> Radius Log Tail</title></head>
<body >
<center><h2>Radius Log Tail</h2>
<h3>Updated at: <font color="#880000">$latestrun</font></h3>
</center>

<xmp>

$errors
</xmp>
</body></html>
EOT