<?php
#
include_once('page.php');
#
global $dbg, $dbgstr;
$dbg = false;
$dbgstr = '';
#
function adddbg($str)
{
 global $dbg, $dbgstr;

 if ($dbg === true)
 {
	if ($dbgstr != '')
		$dbgstr .= "\n";
	$dbgstr .= $str;
 }
}
#
function sq($str)
{
 return str_replace("'", "\\'", $str);
}
#
function dq($str)
{
 return str_replace('"', "\\\"", $str);
}
#
function daysago($val)
{
 if ($val < -13)
	return '';

 if ($val < 60)
	$des = number_format($val,0).'s';
 else
 {
	$val = $val/60;
	if ($val < 60)
		$des = number_format($val,1).'min';
	else
	{
		$val = $val/60;
		if ($val < 24)
			$des = number_format($val,1).'hrs';
		else
		{
			$val = $val/24;
			if ($val < 43)
				$des = number_format($val,1).'days';
			else
			{
				$val = $val/7;
				if ($val < 10000)
					$des = number_format($val,1).'wks';
				else
					$des = '';
			}
		}
	}
 }
 return $des;
}
#
function howlongago($sec)
{
 if ($sec < 60)
	$des = $sec.'s';
 else
 {
	$sec = round($sec/60);
	if ($sec < 60)
		$des = $sec.'min';
	else
	{
		$sec = round($sec/60);
		if ($sec < 24)
		{
			$des = $sec.'hr';
			if ($sec != 1)
				$des .= 's';
		}
		else
		{
			$sec = round($sec/24);
			if ($sec < 9999)
			{
				$des = $sec.'day';
				if ($sec != 1)
					$des .= 's';
			}
			else
				$des = 'never';
		}
	}
 }
 return $des;
}
#
function howmanyhrs($tot, $days = false)
{
 $sec = round($tot);
 if ($sec < 60)
	$des = $sec.'s';
 else
 {
	$min = floor($sec / 60);
	$sec -= $min * 60;
	if ($min < 60)
		$des = $min.'m '.$sec.'s';
	else
	{
		$hr = floor($min / 60);
		$min -= $hr * 60;
		if ($days && $hr > 23)
		{
			$dy = floor($hr / 24);
			$hr -= $dy * 24;
			$des = $dy.'d '.$hr.'hr '.$min.'m '.$sec.'s';
		}
		else
			$des = $hr.'hr '.$min.'m '.$sec.'s';
	}
 }
 return $des;
}
#
function btcfmt($amt)
{
 $amt /= 100000000;
 return number_format($amt, 8);
}
#
function utcd($when, $brief = false)
{
 if ($brief)
	 return gmdate('M-d H:i:s', round($when));
 else
	 return gmdate('Y-m-d H:i:s+00', round($when));
}
#
global $sipre;
# max of uint64 is ~1.845x10^19, 'Z' is above that (10^21)
# max of uint256 is ~1.158x10^77, which is well above 'Y' (10^24)
$sipre = array('', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y');
#
function siprefmt($amt, $dot = 2)
{
 global $sipre;

 $rnd = pow(10, $dot);
 $pref = floor(log10($amt)/3);
 if ($pref < 0)
	$pref = 0;
 if ($pref >= count($sipre))
	$pref = count($sipre)-1;

 $amt = round($rnd * $amt / pow(10, $pref * 3)) / $rnd;
 if ($amt > 999.99 && $pref < (count($sipre)-1))
 {
  $amt /= 1000;
  $pref++;
 }

 if ($pref == 0)
  $dot = 0;
 return number_format($amt, $dot).$sipre[$pref];
}
#
function dsprate($hr)
{
 $hr /= 10000000;
 if ($hr < 100000)
 {
	if ($hr < 0.01)
		$hr = '0GHs';
	else
		$hr = number_format(round($hr)/100, 2).'GHs';
 }
 else
	$hr = number_format(round($hr/1000)/100, 2).'THs';

 return $hr;
}
#
function difffmt($amt)
{
 return siprefmt($amt, 3);
}
#
function emailStr($str)
{
 $all = '/[^A-Za-z0-9_+\.@-]/'; // no space = trim
 $beg = '/^[\.@+-]+/';
 $fin = '/[\.@+_-]+$/';
 return preg_replace(array($all,$beg,$fin), '', $str);
}
#
function passrequires()
{
 return "Passwords require 6 or more characters, including<br>" .
	"at least one of each uppercase, lowercase and a digit, but not Tab";
}
#
function safepass($pass)
{
 if (strlen($pass) < 6)
	return false;

 # Invalid characters
 $p2 = preg_replace('/[\011]/', '', $pass);
 if ($p2 != $pass)
	return false;

 # At least one lowercase
 $p2 = preg_replace('/[a-z]/', '', $pass);
 if ($p2 == $pass)
	return false;

 # At least one uppercase
 $p2 = preg_replace('/[A-Z]/', '', $pass);
 if ($p2 == $pass)
	return false;

 # At least one digit
 $p2 = preg_replace('/[0-9]/', '', $pass);
 if ($p2 == $pass)
	return false;

 return true;
}
#
function loginStr($str)
{
 // Anything but . _ / Tab
 $all = '/[\._\/\011]/';
 return preg_replace($all, '', $str);
}
#
function trn($str)
{
 $rep = str_replace(array('<', '>'), array('&lt;', '&gt;'), $str);
 return $rep;
}
#
function htmler($str)
{
 $srch = array('<','>',"\r\n","\n","\r");
 $rep = array('&lt;','&gt;','<br>','<br>','<br>');
 return str_replace($srch, $rep, $str);
}
#
function cvtdbg()
{
 global $dbg, $dbgstr;

 if ($dbg === false || $dbgstr == '')
	$rep = '';
 else
	$rep = htmler($dbgstr).'<br>';

 return $rep;
}
#
function safeinput($txt, $len = 1024, $lf = true)
{
 $ret = trim($txt);
 if ($ret != '')
 {
	if ($lf === true)
		$ret = preg_replace("/[^ -~\r\n]/", '', $ret);
	else
		$ret = preg_replace('/[^ -~]/', '', $ret);

	if ($len > 0)
		$ret = substr($ret, 0, $len);
 }
 return trim($ret);
}
#
function safetext($txt, $len = 1024)
{
 $tmp = substr($txt, 0, $len);

 $res = '';
 for ($i = 0; $i < strlen($tmp); $i++)
 {
	$ch = substr($tmp, $i, 1);
	if ($ch >= ' ' && $ch <= '~')
		$res .= $ch;
	else
	{
		$c = ord($ch);
		$res .= sprintf('0x%02x', $c);
	}
 }

 if (strlen($txt) > $len)
	$res .= '...';

 return $res;
}
#
function dbd($data, $user)
{
 return "<span class=alert><br>Database is reloading, mining is all OK</span>";
}
#
function dbdown()
{
 gopage(NULL, NULL, 'dbd', 'dbd', def_menu(), '', '', true, false, false);
}
#
function syse($data, $user)
{
 return "<span class=err><br>System error</span>";
}
#
function syserror()
{
 gopage(NULL, NULL, 'syse', 'syse', def_menu(), '', '', true, false, false);
}
#
function f404($data)
{
 return "<span class=alert><br>404</span>";
}
#
function do404()
{
 gopage(NULL, NULL, 'f404', 'f404', def_menu(), '', '', true, false, false);
}
#
function showPage($info, $page, $menu, $name, $user)
{
# If you are doing development, use without '@'
# Then switch to '@' when finished
# include_once("page_$page.php");
 @include_once("page_$page.php");

 $fun = 'show_' . $page;
 if (function_exists($fun))
	$fun($info, $page, $menu, $name, $user);
 else
	do404();
}
#
function showIndex()
{
 showPage(NULL, 'index', def_menu(), '', false);
}
#
function offline()
{
 if (file_exists('./maintenance.txt'))
 {
	$ip = $_SERVER['REMOTE_ADDR'];
	if ($ip != '192.168.1.666')
		gopage(NULL, NULL, file_get_contents('./maintenance.txt'),
			'offline', NULL, '', '', false, false, false);
 }
}
#
offline();
#
session_start();
#
include_once('db.php');
#
function validUserPass($user, $pass, $twofa)
{
 $rep = checkPass($user, $pass, $twofa);
 if ($rep != null)
	$ans = repDecode($rep);
 usleep(500000); // Max twice per second
 if ($rep != null && $ans['STATUS'] == 'ok')
 {
	$key = 'ckp'.rand(1000000,9999999);
	$_SESSION['ckpkey'] = $key;
	$_SESSION[$key] = array('who' => $user, 'id' => $user);
	return true;
 }
 return false;
}
#
function logout()
{
 if (isset($_SESSION['ckpkey']))
 {
	$key = $_SESSION['ckpkey'];

	if (isset($_SESSION[$key]))
		unset($_SESSION[$key]);

	unset($_SESSION['ckpkey']);
 }
}
#
function requestLoginRegReset()
{
 $reg = getparam('Register', true);
 $reg2 = getparam('Reset', false);
 if ($reg !== NULL || $reg2 !== NULL)
 {
	logout();
	return true;
 }
 return false;
}
#
function tryLogInOut()
{
 global $loginfailed;

 // If already logged in, it will ignore User/Pass
 if (isset($_SESSION['ckpkey']))
 {
	$logout = getparam('Logout', false);
	if (!nuem($logout) && $logout == 'Logout')
		logout();
 }
 else
 {
	$login = getparam('Login', false);
	if (nuem($login))
		return;

	$user = getparam('User', false);
	if ($user !== NULL)
		$user = loginStr($user);
	if (nuem($user))
	{
		$loginfailed = true;
		return;
	}

	$pass = getparam('Pass', false);
	if (nuem($pass))
	{
		$loginfailed = true;
		return;
	}

	$twofa = getparam('2fa', false);

	$valid = validUserPass($user, $pass, $twofa);
	if (!$valid)
		$loginfailed = true;
 }
}
#
function validate()
{
 $who = '';
 $whoid = '';

 if (!isset($_SESSION['ckpkey']))
	return array(false, NULL);

 $key = $_SESSION['ckpkey'];
 if (!isset($_SESSION[$key]))
 {
	logout();
	return array(false, NULL);
 }

 if (!isset($_SESSION[$key]['who']))
 {
	logout();
	return array(false, NULL);
 }

 $who = $_SESSION[$key]['who'];

 if (!isset($_SESSION[$key]['id']))
 {
	logout();
	return array(false, NULL);
 }

 $whoid = $_SESSION[$key]['id'];

 return array($who, $whoid);
}
#
function loggedIn()
{
 list($who, $whoid) = validate();
 // false if not logged in
 return $who;
}
#
?>
