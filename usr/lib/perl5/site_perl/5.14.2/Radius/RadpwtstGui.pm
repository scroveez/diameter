#
# RadpwtstGui.pm
# Gui extensions for radpwtst
#
# Author: Mike McCauley (mikem@open.com.au)
# Copyright (C) 1997 Open System Consultants
# $Id: RadpwtstGui.pm,v 1.11 2006/07/04 01:17:48 mikem Exp $

require 5.003;

use Tk;
use Tk::IO;
use strict;
#no warnings qw(redefine);

my $alreadySending;
my $mw = MainWindow->new;
$mw->title('Radius Test Client');

######################################################################
# Set up main menu bar
my $menu = $mw->Frame(-relief => 'raised', 
		      -borderwidth => 2);
$menu->pack(-fill => 'x');


######################################################################
# Set up File menu
my $fileM = $menu->Menubutton(-text => 'File', 
			   -underline => 0);
$fileM->command(-label => 'Exit', 
		-command => \&cleanandexit);

######################################################################
# Set up Options menu
my $optionsM = $menu->Menubutton(-text => 'Options', 
			   -underline => 0);
$optionsM->cascade(-label => 'Trace Level', 
		-underline => 0);


######################################################################
# Set up Options->Trace Level menu
my $traceM = $optionsM->cget(-menu);
my $traceC = $traceM->Menu;
$optionsM->entryconfigure('Trace Level', -menu => $traceC);

$traceC->radiobutton(-label => 'None', 
		     -variable => \$main::trace_level,
		     -value => 0);
$traceC->radiobutton(-label => 'Brief', 
		     -variable => \$main::trace_level,
		     -value => 1);
$traceC->radiobutton(-label => 'Detailed', 
		     -variable => \$main::trace_level,
		     -value => 4);

$fileM->pack(-side => 'left');
$optionsM->pack(-side => 'left');


######################################################################
# Set up Tool bar
my $tools = $mw->Frame(-relief => 'sunken', 
		       -borderwidth => 2);

my $sendButton = $tools->Button(-text => 'Send',
			     -command => \&send)
    ->pack(-side => 'left');
my $stopButton = $tools->Button(-text => 'Stop',
			     -state => 'disabled',
			     -command => \&stop)
    ->pack(-side => 'left');
$tools->pack(-side => 'top',
	     -expand => 'no',
	     -fill => 'x');

######################################################################
# Set up attribute configuration area
my $attr = $mw->Frame;

# Frame for attributes
my $af1 = $attr->Frame(-borderwidth => '2', -relief => 'groove');

$af1->Label(-text => 'Send these attributes:')
    ->grid(-sticky => 'w', 
	   -columnspan => 2);
$af1->Label(-text => 'User-Name')
    ->grid(-row => 1,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::user)
    ->grid(-row => 1,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'User-Password')
    ->grid(-row => 2,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::password)
    ->grid(-row => 2,
	   -column => 1,
	   -sticky => 'ew');

$af1->Checkbutton(-text => 'Use CHAP',
		  -variable => \$main::chap)
    ->grid(-row => 3,
	   -column => 1,
	   -sticky => 'w');

$af1->Label(-text => 'Service-Type')
    ->grid(-row => 4,
	   -sticky => 'e');
my @options = $main::dict->valuesForAttribute('Service-Type');
$af1->Optionmenu(-options => \@options,
		 -textvariable => \$main::service_type)
    ->grid(-row => 4,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'NAS-Address')
    ->grid(-row => 5,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::nas_ip_address)
    ->grid(-row => 5,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'NAS-Port')
    ->grid(-row => 6,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::nas_port)
    ->grid(-row => 6,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'Acct-Delay-Time')
    ->grid(-row => 7,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::delay_time)
    ->grid(-row => 7,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'Acct-Session-Time')
    ->grid(-row => 8,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::session_time)
    ->grid(-row => 8,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'Acct-Input-Octets')
    ->grid(-row => 9,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::input_octets)
    ->grid(-row => 9,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'Acct-Output-Octets')
    ->grid(-row => 10,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::output_octets)
    ->grid(-row => 10,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'Acct-Session-Id')
    ->grid(-row => 11,
	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::session_id)
    ->grid(-row => 11,
	   -column => 1,
	   -sticky => 'ew');

$af1->Label(-text => 'Framed-IP-Address')
    ->grid(-row => 12,
 	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::framed_ip_address)
    ->grid(-row => 12,
 	   -column => 1,
 	   -sticky => 'ew');
 
$af1->Label(-text => 'Calling-Station-ID')
    ->grid(-row => 13,
 	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::calling_station_id)
    ->grid(-row => 13,
 	   -column => 1,
 	   -sticky => 'ew');
$af1->Label(-text => 'Called-Station-ID')
    ->grid(-row => 14,
 	   -sticky => 'e');
$af1->Entry(-textvariable => \$main::called_station_id)
    ->grid(-row => 14,
 	   -column => 1,
 	   -sticky => 'ew');

######################################################################
# Frame for messages to send
my $af2 = $attr->Frame(-borderwidth => '2', -relief => 'groove');

$af2->Label(-text => 'In these requests:')
    ->grid(-sticky => 'nw');
$af2->Checkbutton(-text => 'Authentication',
		  -variable => \$main::send_auth)
    ->grid(-sticky => 'nw');
$af2->Checkbutton(-text => 'Accounting Start',
		  -variable => \$main::send_acct_start)
    ->grid(-sticky => 'nw');
$af2->Checkbutton(-text => 'Accounting Stop',
		  -variable => \$main::send_acct_stop)
    ->grid(-sticky => 'nw');
$af2->Checkbutton(-text => 'Accounting On',
		  -variable => \$main::send_acct_on)
    ->grid(-sticky => 'nw');
$af2->Checkbutton(-text => 'Accounting Off',
		  -variable => \$main::send_acct_off)
    ->grid(-sticky => 'nw');
$af2->Checkbutton(-text => 'Server Status',
		  -variable => \$main::send_server_status)
    ->grid(-sticky => 'nw');

######################################################################
# Set up server configuration area
my $af3 = $attr->Frame(-borderwidth => '2', -relief => 'groove');

$af3->Label(-text => 'To this server:')
    ->grid(-row => 0,
	   -sticky => 'w', 
	   -columnspan => 2);
$af3->Label(-text => 'Name')
    ->grid(-row => 1,
	   -sticky => 'e');
$af3->Entry(-textvariable => \$main::desthost)
    ->grid(-row => 1,
	   -column => 1,
	   -sticky => 'ew');
$af3->Label(-text => 'Secret')
    ->grid(-row => 2,
	   -sticky => 'e');
$af3->Entry(-textvariable => \$main::secret)
    ->grid(-row => 2,
	   -column => 1,
	   -sticky => 'ew');
$af3->Label(-text => 'Auth port')
    ->grid(-row => 3,
	   -sticky => 'e');
$af3->Entry(-textvariable => \$main::auth_port)
    ->grid(-row => 3,
	   -column => 1,
	   -sticky => 'ew');
$af3->Label(-text => 'Acct port')
    ->grid(-row => 4,
	   -sticky => 'e');
$af3->Entry(-textvariable => \$main::acct_port)
    ->grid(-row => 4,
	   -column => 1,
	   -sticky => 'ew');
$af3->Label(-text => 'Timeout (s)')
    ->grid(-row => 5,
	   -sticky => 'e');
$af3->Entry(-textvariable => \$main::replyTimeout)
    ->grid(-row => 5,
	   -column => 1,
	   -sticky => 'ew');
$af3->Label(-text => 'Iterations')
    ->grid(-row => 6,
	   -sticky => 'e');
$af3->Entry(-textvariable => \$main::iterations)
    ->grid(-row => 6,
	   -column => 1,
	   -sticky => 'ew');

$af1->pack(-side => 'left');
$af2->pack(-side => 'left', -anchor => 'n');
$af3->pack(-side => 'left', -anchor => 'n');
$attr->pack(-fill => 'x');



######################################################################
# Set up diagnostic output
my $trace_out = $mw->Scrolled('Text',
			      -relief => 'sunken', 
			      -borderwidth => 2,
			      -setgrid => 'true',
			      -height => 20,
			      -scrollbars => 'e');
$trace_out->pack(-expand => 'yes',
		 -fill => 'both');
$trace_out->tagConfigure('failTag', foreground => 'red');
$trace_out->tagConfigure('successTag', foreground => 'green');

MainLoop;

sub waitForSocket
{
    my ($s, $timeout) = @_;

    my $readable = 0;
    my $timed_out = 0;
    $mw->fileevent($s, 'readable' => sub { $readable = 1; });
    my $timerid = $mw->after($timeout * 1000, sub { $timed_out = 1;});
    while (!$readable && !$timed_out&& !$main::stopSending)
    {
	$mw->DoOneEvent(Tk::ALL_EVENTS);
    }
    $mw->afterCancel($timerid);
    return $readable;
}

# These will be from errors inside the library. Always show them in the GUI
sub log
{
    my ($priority, $s) = @_;

    $trace_out->insert('end', "$s\n");
}

sub announceSending
{
    my ($msg) = @_;
    $trace_out->insert('end', "sending $msg...") if $main::trace_level >= 1;
}

sub announceSuccess
{
    my ($msg) = @_;
    $trace_out->insert('end', "$msg\n", 'successTag') 
	if $main::trace_level >= 1;
}

sub announceFailure
{
    my ($msg) = @_;
    
    $main::errors++;
    $trace_out->insert('end', "$msg\n", 'failTag') 
	if $main::trace_level >= 1;
}

sub announceRejection
{
    my ($msg) = @_;
    
    $main::reject++;
    $trace_out->insert('end', "$msg\n", 'failTag') 
	if $main::trace_level >= 1;
}

sub announce
{
    my ($msg) = @_;

    $trace_out->insert('end', $msg);
}

sub showdump
{
    my ($p) = @_;

    $trace_out->insert('end', $p->dump);
}

sub send
{
    # Guard against recursion
    if (!$alreadySending)
    {
	$alreadySending++;
	$sendButton->configure(-state => 'disabled');
	$stopButton->configure(-state => 'active');
	&sendAll;
	$alreadySending--;
	$sendButton->configure(-state => 'active');
	$stopButton->configure(-state => 'disabled');
	$trace_out->see('end');
    }
}

sub stop
{
    $main::stopSending = 1;
}

sub cleanandexit
{
    # Need to clean up before exiting, else get a core dump
    # This destroy will cause MainLoop to return
    $mw->destroy;
}


1;
