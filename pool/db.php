<?php
#
include_once('socket.php');
include_once('base.php');
#
# List of db functions to call and get the results back from ckdb
# From homeInfo() and the rest after that
# The repDecode() result is an array of all ckdb result field names and
#  their values
# Also included:
#	['ID'] the id sent
#	['STAMP'] the ckdb reply timestamp
#	['STATUS'] the ckdb reply status (!'ok' = error)
#	['ERROR'] if status != 'ok', the error message reply
# The reply is false if the ckdb return data was corrupt
# The repData() result is:
#	['ID'] the id sent
#	['STAMP'] the ckdb reply timestamp
#	['STATUS'] the ckdb reply status (!'ok' = error)
#	['DATA'] the rest of the ckdb reply, or '' on error
#	['ERROR'] if status not 'ok', the error message reply
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
function repData($rep)
{
 global $send_sep;

 $fix = preg_replace("/[\n\r]*$/",'',$rep);
 $major = explode($send_sep, $fix, 4);
 if (count($major) < 3)
	return false;

 $ans = array();

 $ans['ID'] = $major[0];
 $ans['STAMP'] = $major[1];
 $ans['STATUS'] = $major[2];
 $ans['DATA'] = '';
 if ($major[2] == 'ok')
 {
	$ans['ERROR'] = null;
	if (isset($major[3]))
		$ans['DATA'] = $major[3];
 }
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
# Convenience function
function zeip()
{
 return $_SERVER['REMOTE_ADDR'];
}
#
# user administration overrided
function adm($user, &$msg)
{
 global $fld_sep, $val_sep;
 if ($user == 'Kano')
 {
	$admin = getparam('admin', true);
	if (!nuem($admin))
		$msg .= $fld_sep . 'admin' . $val_sep . $admin;
 }
}
#
function fldEncode($flds, $name, $first)
{
 global $fld_sep, $val_sep;
 if ($first)
	$rep = '';
 else
	$rep = $fld_sep;
 $rep .= $name . $val_sep;
 if (isset($flds[$name]))
	$rep .= $flds[$name];
 return $rep;
}
#
function msgEncode($cmd, $id, $fields, $user)
{
 global $send_sep, $fld_sep, $val_sep;

 $t = time() % 10000;
 $msg = $cmd . $send_sep . $id.$t . $send_sep;
 foreach ($fields as $name => $value)
	$msg .= $name . $val_sep . $value . $fld_sep;
 $msg .= 'createcode' . $val_sep . 'php' . $fld_sep;
 $msg .= 'createby' . $val_sep . $user . $fld_sep;
 $msg .= 'createinet' . $val_sep . zeip();
 adm($user, $msg);
 return $msg;
}
#
function getStats($user)
{
 if ($user === null)
	$msg = msgEncode('homepage', 'home', array(), $user);
 else
	$msg = msgEncode('homepage', 'home', array('username'=>$user), $user);
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
//	if ($ans['lastblock'] == '?')
//	{
//		$ans['lastblock'] = 1401237522;
//		$ans['lastblock'] = 1403819191;
//		$ans['lastblock'] = 1407113822;
//	}
 }

 return $ans;
}
#
function checkPass($user, $pass)
{
 $passhash = myhash($pass);
 $flds = array('username' => $user, 'passwordhash' => $passhash);
 $msg = msgEncode('chkpass', 'chkpass', $flds, $user);
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
 $msg = msgEncode('newpass', 'newpass', $flds, $user);
 $rep = sendsockreply('setPass', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function resetPass($user, $newpass)
{
 $newhash = myhash($newpass);
 $flds = array('username' => $user, 'newhash' => $newhash);
 $msg = msgEncode('newpass', 'newpass', $flds, $user);
 $rep = sendsockreply('resetPass', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function userReg($user, $email, $pass)
{
 $passhash = myhash($pass);
 $flds = array('username' => $user, 'emailaddress' => $email, 'passwordhash' => $passhash);
 $msg = msgEncode('adduser', 'reg', $flds, $user);
 $rep = sendsockreply('userReg', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function userSettings($user, $email = null, $addr = null, $pass = null)
{
 $tmo = false;
 $flds = array('username' => $user);
 if ($email != null)
	$flds['email'] = $email;
 if ($addr != null)
 {
	$rows = count($addr);
	$i = 0;
	foreach ($addr as $ar)
	{
		$flds['address:'.$i] = $ar['addr'];
		// optional - missing = use default
		if (isset($ar['ratio']))
			$flds['ratio:'.$i] = $ar['ratio'];
		$i++;
	}
	$flds['rows'] = $rows;
	$tmo = 3; # 3x the timeout
 }
 if ($pass != null)
	$flds['passwordhash'] = myhash($pass);
 $msg = msgEncode('usersettings', 'userset', $flds, $user);
 $rep = sendsockreply('userSettings', $msg, $tmo);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function workerSet($user, $settings)
{
 $flds = array_merge(array('username' => $user), $settings);
 $msg = msgEncode('workerset', 'workerset', $flds, $user);
 $rep = sendsockreply('workerSet', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getAllUsers($user)
{
 $flds = array();
 $msg = msgEncode('allusers', 'all', $flds, $user);
 $rep = sendsockreply('getAllUsers', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getWorkers($user, $stats = 'Y')
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user, 'stats' => $stats);
 $msg = msgEncode('workers', 'work', $flds, $user);
 $rep = sendsockreply('getWorkers', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getPercents($user, $stats = 'Y')
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user, 'stats' => $stats, 'percent' => 'Y');
 $msg = msgEncode('workers', 'work', $flds, $user);
 $rep = sendsockreply('getPercents', $msg);
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
 $msg = msgEncode('payments', 'pay', $flds, $user);
 $rep = sendsockreply('getPayments', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getMPayouts($user)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user);
 $msg = msgEncode('mpayouts', 'mp', $flds, $user);
 $rep = sendsockreply('getMPayments', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getShifts($user, $workers = null)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user);
 if ($workers !== null)
	$flds['select'] = $workers;
 $msg = msgEncode('shifts', 'shift', $flds, $user);
 $rep = sendsockreply('getShifts', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getShiftData($user, $workers = null)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user);
 if ($workers !== null)
	$flds['select'] = $workers;
 $msg = msgEncode('shifts', 'shift', $flds, $user);
 $rep = sendsockreply('getShifts', $msg);
 if (!$rep)
	dbdown();
 return repData($rep);
}
#
function getPShifts($user)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user);
 $msg = msgEncode('pshift', 'pshift', $flds, $user);
 $rep = sendsockreply('getPShifts', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getPShiftData($user)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user);
 $msg = msgEncode('pshift', 'pshift', $flds, $user);
 $rep = sendsockreply('getPShifts', $msg);
 if (!$rep)
	dbdown();
 return repData($rep);
}
#
function getBlocks($user)
{
 if ($user == false)
	showIndex();
 $flds = array();
 $msg = msgEncode('blocklist', 'blk', $flds, $user);
 $rep = sendsockreply('getBlocks', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
function getUserInfo($user)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user);
 $msg = msgEncode('userinfo', 'usr', $flds, $user);
 $rep = sendsockreply('getUserInfo', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
# e.g. $atts = array('ua_Reset.str' => 'FortyTwo',
#			'ua_Reset.date' => 'now+3600')
#			'ua_Tanuki.str' => 'Meme',
#			'ua_Tanuki.date' => 'now');
function setAtts($user, $atts)
{
 if ($user == false)
	showIndex();
 $flds = array_merge(array('username' => $user), $atts);
 $msg = msgEncode('setatts', 'setatts', $flds, $user);
 $rep = sendsockreply('setAtts', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
# e.g. $attlist = 'Reset.str,Reset.dateexp,Tanuki.str,Tanuki.date'
function getAtts($user, $attlist)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user, 'attlist' => $attlist);
 $msg = msgEncode('getatts', 'getatts', $flds, $user);
 $rep = sendsockreply('getAtts', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
# e.g. $attlist = 'Reset,Tanuki'
# effectively makes the useratts disappear (i.e. expired)
function expAtts($user, $attlist)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user, 'attlist' => $attlist);
 $msg = msgEncode('expatts', 'expatts', $flds, $user);
 $rep = sendsockreply('expAtts', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
# e.g. $opts = array('oc_BlockAmountHalf.value' => '25',
#			'oc_BlockAmountHalf.height' => '210000',
#			'oc_BlockAmountHalf.date' => '2012-11-28 15:25:01+00',
#			'oc_BlockAmountQuarter.value' => '12.5',
#			'oc_BlockAmountQuarter.height' => '420000');
# *.value is always required
function setOpts($user, $opts)
{
 if ($user == false)
	showIndex();
 $flds = array_merge(array('username' => $user), $opts);
 $msg = msgEncode('setopts', 'setopts', $flds, $user);
 $rep = sendsockreply('setOpts', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
# e.g. $optlist = 'KWebURL,BlockAmountQuarter'
function getOpts($user, $optlist)
{
 if ($user == false)
	showIndex();
 $flds = array('username' => $user, 'optlist' => $optlist);
 $msg = msgEncode('getopts', 'getopts', $flds, $user);
 $rep = sendsockreply('getOpts', $msg);
 if (!$rep)
	dbdown();
 return repDecode($rep);
}
#
?>
