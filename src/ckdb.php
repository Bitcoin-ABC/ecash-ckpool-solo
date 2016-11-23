<?php
#
global $socket_name_def, $socket_dir_def, $socket_file_def;
global $socket_name, $socket_dir, $socket_file;
#
$socket_name_def = 'ckdb';
$socket_dir_def = '/opt/';
$socket_file_def = 'listenercmd';
#
$socket_name = $socket_name_def;
$socket_dir = $socket_dir_def;
$socket_file = $socket_file_def;
#
include_once('../pool/socket.php');
#
function getsock2($fun, $tmo)
{
 global $socket_name, $socket_dir, $socket_file;
 return _getsock($fun, "$socket_dir$socket_name/$socket_file", $tmo);
}
#
function msg($line, $tabs, $tmo = false)
{
 global $fld_sep, $val_sep;

 if ($tabs)
	$line = str_replace("TAB", "\t", $line);
 $fun = 'stdin';
 $ret = false;
 $socket = getsock2($fun, $tmo);
 if ($socket !== false)
 {
	$ret = dosend($fun, $socket, $line);
	if ($ret !== false)
		$ret = readsockline($fun, $socket);

	socket_close($socket);
 }
 return $ret;
}
#
function usAge($a0)
{
 global $socket_name_def, $socket_dir_def, $socket_file_def;
 echo "usAge: php $a0 [-t] [name [dir [socket]]]\n";
 echo " -t = don't convert 'TAB' to a tab character\n";
 echo " default name = $socket_name_def\n";
 echo " default dir = $socket_dir_def\n";
 echo " default socket = $socket_file_def\n";
 echo " i.e. $socket_dir_def$socket_name_def/$socket_file_def\n";
 exit(1);
}
#
$tabs = true;
#
if (count($argv) > 1)
{
 if ($argv[1] == '-?' || $argv[1] == '-h' || $argv[1] == '-help'
 ||  $argv[1] == '--help')
	usAge($argv[0]);

 $a = 1;
 if ($argv[$a] == '-t')
 {
	$tabs = false;
	$a++;
 }
 $socket_name = $argv[$a++];
 if (count($argv) > $a)
 {
	$socket_dir = $argv[$a++];
	if (count($argv) > $a)
		$socket_file = $argv[$a];
 }
}
#
while ($line = fgets(STDIN))
{
 $line = trim($line);
 if (strlen($line) > 0)
 {
	$rep = msg($line, $tabs);
	if ($rep === false)
		echo "Failed\n";
	else
		echo "$rep\n";
 }
}
?>
