<?php
#
# See function sendsockreply($fun, $msg, $tmo) at the end
#
function socktmo($socket, $factor)
{
 # default timeout factor
 if ($factor === false)
	$factor = 1;

 # on a slower server increase this base value
 $tmo = 8;

 $usetmo = $tmo * $factor;
 $sec = floor($usetmo);
 $usec = floor(($usetmo - $sec) * 1000000);
 $tmoval = array('sec' => $sec, 'usec' => $usec);
 socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, $tmoval);
 socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, $tmoval);
}
#
# Note that $port in AF_UNIX should be the socket filename
function _getsock($fun, $port, $tmo, $unix=true)
{
 $socket = null;
 if ($unix === true)
	 $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
 else
	 $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
 if ($socket === false || $socket === null)
 {
	$sle = socket_last_error();
	$sockerr = socket_strerror($sle);
	$msg = "$fun() _getsock() create($port) failed";
	error_log("CKPERR: $msg ($sle) '$sockerr'");
	return false;
 }

 if ($unix === true)
	$res = socket_connect($socket, $port, NULL);
 else
	$res = socket_connect($socket, '127.0.0.1', $port);
 if ($res === false)
 {
	// try 3x
	if ($unix === true)
		$res = socket_connect($socket, $port);
	else
	{
		sleep(2);
		$res = socket_connect($socket, '127.0.0.1', $port);
	}
	if ($res === false)
	{
		if ($unix === true)
			$res = socket_connect($socket, $port);
		else
		{
			sleep(5);
			$res = socket_connect($socket, '127.0.0.1', $port);
		}
		if ($res === false)
		{
			$sle = socket_last_error();
			$sockerr = socket_strerror($sle);
			if ($unix === true)
				$msg = "$fun() _getsock() connect($port) failed 3x";
			else
				$msg = "$fun() _getsock() connect($port) failed 3x (+2+5s sleep)";
			error_log("CKPERR: $msg ($sle) '$sockerr'");
			socket_close($socket);
			return false;
		}
	}
 }
 # Avoid getting locked up for long
 socktmo($socket, $tmo);
 # Enable timeout
 socket_set_block($socket);
 return $socket;
}
#
function getsock($fun, $tmo)
{
 return _getsock($fun, '/opt/ckdb/listenerweb', $tmo);
}
#
function readsockline($fun, $socket)
{
 $siz = socket_read($socket, 4, PHP_BINARY_READ);
 if ($siz === false)
 {
	$sle = socket_last_error();
	$sockerr = socket_strerror($sle);
	$msg = "$fun() readsockline() failed";
	error_log("CKPERR: $msg ($sle) '$sockerr'");
	return false;
 }
 if (strlen($siz) != 4)
 {
	$msg = "$fun() readsockline() short 4 read got ".strlen($siz);
	error_log("CKPERR: $msg");
	return false;
 }
 $len = ord($siz[0]) + ord($siz[1])*256 +
	ord($siz[2])*65536 + ord($siz[3])*16777216;
 $ans = '';
 $left = $len;
 while ($left > 0)
 {
	$line = socket_read($socket, $left, PHP_BINARY_READ);
	if ($line === false)
	{
		$sle = socket_last_error();
		$sockerr = socket_strerror($sle);
		$msg = "$fun() readsockline() $left failed (len=$len)";
		error_log("CKPERR: $msg ($sle) '$sockerr'");
		return false;
	}
	$red = strlen($line);
	if ($red == 0)
	{
		$msg = "$fun() readsockline() incomplete (".($len-$left)." vs $len)";
		$sub = "'".substr($line, 0, 30)."'";
		if (strlen($line) > 30)
			$sub .= '...';
		error_log("CKPERR: $msg $sub");
		return false;
	}
	$left -= $red;
	$ans .= $line;
 }
 return $ans;
}
#
function dosend($fun, $socket, $msg)
{
 $msg .= "\n";
 $len = strlen($msg);

 $sen = $len;
 $siz = chr($sen % 256);
 $sen = $sen >> 8;
 $siz .= chr($sen % 256);
 $sen = $sen >> 8;
 $siz .= chr($sen % 256);
 $sen = $sen >> 8;
 $siz .= chr($sen % 256);

 $msg = $siz . $msg;

 $len += 4;
 $left = $len;
 $ret = false;
 while ($left > 0)
 {
	$res = socket_write($socket, substr($msg, 0 - $left), $left);
	if ($res === false)
	{
		$sockerr = socket_strerror(socket_last_error());
		$msg = "$fun() sendsock() failed";
		error_log("CKPERR: $msg '$sockerr'");
		break;
	}
	if ($res == 0)
	{
		$msg = "$fun() sendsock() incomplete (".($len-$left)." vs $len)";
		error_log("CKPERR: $msg");
		break;
	}
	$left -= $res;
 }
 if ($left == 0)
	$ret = true;

 return $ret;
}
#
function sendsock($fun, $msg, $tmo = false)
{
 $ret = false;
 $socket = getsock($fun, $tmo);
 if ($socket !== false)
 {
	$ret = dosend($fun, $socket, $msg);
	socket_close($socket);
 }
 return $ret;
}
#
# This is the only function in here you call
# You pass it a string $fun for debugging
# and the data $msg to send to ckdb
# and it returns $ret = false on error or $ret = the string reply
#
# Alerts are always tagged on the end as: $fld_sep alert $val_sep text
# There's allowed to be more than one. They are removed
#
function sendsockreply($fun, $msg, $tmo = false)
{
 global $fld_sep, $val_sep, $alrts;

 $ret = false;
 $socket = getsock($fun, $tmo);
 if ($socket !== false)
 {
	$ret = dosend($fun, $socket, $msg);
	if ($ret !== false)
		$ret = readsockline($fun, $socket);

	socket_close($socket);
 }
 $al = $fld_sep . 'alert' . $val_sep;
 if ($ret !== false and strpos($ret, $al) !== false)
 {
	$all = explode($al, $ret);
	$ret = $all[0];
	$skip = true;
	foreach ($all as $lrt)
	{
		if ($skip)
			$skip = false;
		else
			// Discard duplicates
			$alrts[preg_replace("/[\n\r]*$/",'',$lrt)] = 1;
	}
 }
 return $ret;
}
#
?>
