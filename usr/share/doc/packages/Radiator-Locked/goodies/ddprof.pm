#Hello,
#
#I'm local maintainer of Radiator at Iskon, Croatian second largest ISP.
#
#During my work I needed functions that would point place in radiator
#code where the significant time is spent. So I wrote small and simple
#package that was able to do profiling. Maybe it would not be a bad
#thing to include such thing in Radiator package, and place a few
#calls to it (controled by sonfiguration options) in Handler.pm, so
#that administrators could easily identify which phase of request
#handling is slowing down the process (or they can use it in hooks).
#
#I guess there are better ways to implement funcionality that following
#modules provide, so I send it just to illustrate my idea. I give away
#any copyrights on it. Use freely,
#
#Best regards,
#Damir

package ddprof;

use Time::HiRes;

use vars qw(%K);

sub prof_start
{
    my ($a) = @_;
    $K{$a} = Time::HiRes::time;
}

sub prof_stop
{
    my ($a, $b) = @_;
    my @x = localtime(int $K{$a});
    my $l = Time::HiRes::time - $K{$a};
    $l = substr($l, 0, 5);
    delete $K{$a};
    if (open(L, ">>/tmp/proflog")) {
      my $wt;
      $a ||= '';
      $b ||= '';
      $wt = sprintf("%04d-%02d-%02d %02d:%02d:%02d", $x[5]+1900, $x[4]+1, $x[3], $x[2], $x[1], $x[0]);
      print L "$wt $a took $l; $b\n";
      close L;
    }
}

1;
