<?php
#
# See function sendsockreply($fun, $msg) at the end
#
# Note that $port in AF_UNIX should be the socket filename
function _getsock($fun, $port, $unix=true)
{
 $socket = null;
 if ($unix === true)
	 $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
 else
	 $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
 if ($socket === false || $socket === null)
 {
	$sockerr = socket_strerror(socket_last_error());
	$msg = "$fun() _getsock() create($port) failed";
	error_log("CKPERR: $msg '$sockerr'");
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
			$sockerr = socket_strerror(socket_last_error());
			if ($unix === true)
				$msg = "$fun() _getsock() connect($port) failed 3x";
			else
				$msg = "$fun() _getsock() connect($port) failed 3x (+2+5s sleep)";
			error_log("CKPERR: $msg '$sockerr'");
			socket_close($socket);
			return false;
		}
	}
 }
 return $socket;
}
#
function getsock($fun)
{
 return _getsock($fun, '/opt/ckdb/listener');
}
#
function readsockline($fun, $socket)
{
 $siz = socket_read($socket, 4);
 if ($siz === false)
 {
	$sockerr = socket_strerror(socket_last_error());
	$msg = "$fun() readsockline() failed";
	error_log("CKPERR: $msg '$sockerr'");
	return false;
 }
 if (strlen($siz) != 4)
 {
	$msg = "$fun() readsockline() short read $siz vs ".strlen($siz);
	error_log("CKPERR: $msg");
	return false;
 }
 $len = ord($siz[0]) + ord($siz[1])*256 +
	ord($siz[2])*65536 + ord($siz[3])*16777216;
 $line = socket_read($socket, $len);
 if ($line === false)
 {
	$sockerr = socket_strerror(socket_last_error());
	$msg = "$fun() readsockline() failed";
	error_log("CKPERR: $msg '$sockerr'");
	return false;
 }
 else
	if (strlen($line) != $len)
	{
		$msg = "$fun() readsockline() incomplete ($len)";
		error_log("CKPERR: $msg '$line'");
		return false;
	}

 return $line;
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

 $left = $len + 4;
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
	else
		$left -= $res;
 }
 if ($left == 0)
	$ret = true;

 return $ret;
}
#
function sendsock($fun, $msg)
{
 $ret = false;
 $socket = getsock($fun);
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
function sendsockreply($fun, $msg)
{
 $ret = false;
 $socket = getsock($fun);
 if ($socket !== false)
 {
	$ret = dosend($fun, $socket, $msg);
	if ($ret !== false)
		$ret = readsockline($fun, $socket);

	socket_close($socket);
 }
 return $ret;
}
#
?>
