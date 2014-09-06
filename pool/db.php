<?php
#
include_once('socket.php');
include_once('base.php');
#
# List of db functions to call and get the results back from ckdb
# From homeInfo() and the rest after that
# The result is an array of all ckdb result field names and their values
# Also included:
#	['ID'] the id sent
#	['STAMP'] the ckdb reply timestamp
#	['STATUS'] the ckdb reply status (!'ok' = error)
#	['ERROR'] if status not 'ok' the error message reply
# The reply is false if the ckdb return data was corrupt
#
global $send_sep, $fld_sep, $val_sep;
$send_sep = '.';
$fld_sep = Chr(0x9);
$val_sep = '=';
#
function myhash($str)
{
 return strtolower(hash('sha256', $str));
}
#
function repDecode($rep)
{
 global $send_sep, $fld_sep, $val_sep;

 $fix = preg_replace("/[\n\r]*$/",'',$rep);
 $major = explode($send_sep, $fix, 4);
 if (count($major) < 3)
	return false;

 $ans = array();
 if (count($major) > 3)
 {
	$flds = explode($fld_sep, $major[3]);
	foreach ($flds as $fld)
	{
		if (strlen($fld) > 0)
		{
			$nameval = explode($val_sep, $fld, 2);
			if (count($nameval) > 1)
				$ans[$nameval[0]] = $nameval[1];
			else
				$ans[$nameval[0]] = '';
		}
	}
 }

 $ans['ID'] = $major[0];
 $ans['STAMP'] = $major[1];
 $ans['STATUS'] = $major[2];
 if ($major[2] == 'ok')
	$ans['ERROR'] = null;
 else
 {
	if (isset($major[3]))
		$ans['ERROR'] = $major[3];
	else
		$ans['ERROR'] = 'system error';
 }

 return $ans;
}
#
function msgEncode($cmd, $id, $fields)
{
 global $send_sep, $fld_sep, $val_sep;

 $t = time() % 10000;
 $msg = $cmd . $send_sep . $id.$t;
 $first = true;
 foreach ($fields as $name => $value)
 {
	if ($first === true)
	{
		$msg .= $send_sep;
		$first = false;
	}
	else
		$msg .= $fld_sep;

	$msg .= $name . $val_sep . $value;
 }
 return $msg;
}
#
function getStats($user)
{
 if ($user === null)
	$msg = msgEncode('homepage', 'home', array());
 else
	$msg = msgEncode('homepage', 'home', array('username'=>$user));
 return $msg;
}
#
function homeInfo($user)
{
 $msg = getStats($user);
 $rep = sendsockreply('homepage', $msg);
 if ($rep === false)
	$ans = false;
 else
 {
	$ans = repDecode($rep);
	if ($ans['lastblock'] == '?')
	{
//		$ans['lastblock'] = 1401237522;
//		$ans['lastblock'] = 1403819191;
		$ans['lastblock'] = 1407113822;
	}
 }

 return $ans;
}
#
function checkPass($user, $pass)
{
 $passhash = myhash($pass);
 $flds = array('username' => $user, 'passwordhash' => $passhash);
 $msg = msgEncode('chkpass', 'log', $flds);
 $rep = sendsockreply('checkPass', $msg);
 if (!$rep)
	dbdown();
 return $rep;
}
#
function setPass($user, $oldpass, $newpass)
{
 $oldhash = myhash($oldpass);
 $newhash = myhash($newpass);
 $flds = array('username' => $user, 'oldhash' => $oldhash, 'newhash' => $newhash);
 $msg = msgEncode('newpass', 'log', $flds);
 $rep = sendsockreply('setPass', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function userReg($user, $email, $pass)
{
 $passhash = myhash($pass);
 $flds = array('username' => $user, 'emailaddress' => $email, 'passwordhash' => $passhash);
 $msg = msgEncode('adduser', 'reg', $flds);
 $rep = sendsockreply('userReg', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function userSettings($user, $email = null, $addr = null, $pass = null)
{
 $flds = array('username' => $user);
 if ($email != null)
	$flds['email'] = $email;
 if ($addr != null)
	$flds['address'] = $addr;
 if ($pass != null)
	$flds['passwordhash'] = myhash($pass);
 $msg = msgEncode('usersettings', 'userset', $flds);
 $rep = sendsockreply('userSettings', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getAllUsers()
{
 $flds = array();
 $msg = msgEncode('allusers', 'all', $flds);
 $rep = sendsockreply('getAllUsers', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getWorkers($user)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user, 'stats' => 'Y');
 $msg = msgEncode('workers', 'work', $flds);
 $rep = sendsockreply('getWorkers', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getPayments($user)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user);
 $msg = msgEncode('payments', 'pay', $flds);
 $rep = sendsockreply('getPayments', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getBlocks($user)
{
 if ($user == false)
	showIndex();
 $flds = array();
 $msg = msgEncode('blocklist', 'blk', $flds);
 $rep = sendsockreply('getBlocks', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
?>
