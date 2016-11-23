<?php
#
include_once('email.php');
#
function allow_reset($error)
{
 $pg = '<br><br><table cellpadding=5 cellspacing=0 border=1><tr><td class=dc>';

 $pg .= '<h1>Password Reset</h1>';
 if ($error !== null)
	$pg .= "<br><b>$error - please try again</b><br><br>";
 $pg .= makeForm('reset');
 $pg .= "
<table>
<tr><td class=dc colspan=2>Enter a new password twice.<br>
" . passrequires() . "
<input type=hidden name=k value=reset></td></tr>
<tr><td class=dr>Password:</td>
 <td class=dl><input type=password name=pass></td></tr>
<tr><td class=dr>Retype Password:</td>
 <td class=dl><input type=password name=pass2></td></tr>
<tr><td class=dr><span class=st1>*</span>2nd Authentication:</td>
 <td class=dl><input name=2fa size=10></td></tr>
<tr><td colspan=2 class=dc><br><font size=-1><span class=st1>*</span>
 Leave blank if you haven't enabled it</font></td></tr>
<tr><td>&nbsp;</td>
 <td class=dl><input type=submit name=Update value=Update></td></tr>
</table>
</form>";

 $pg .= '</td></tr></table>';

 return $pg;
}
#
function yok()
{
 $pg = '<h1>Password Reset</h1>';
 $pg .= '<br>Your password has been reset,';
 $pg .= '<br>login with it on the Home page.';
 return $pg;
}
#
function resetfail()
{
 if (isset($_SESSION['reset_user']))
	unset($_SESSION['reset_user']);
 if (isset($_SESSION['reset_hash']))
	unset($_SESSION['reset_hash']);
 if (isset($_SESSION['reset_email']))
	unset($_SESSION['reset_email']);
 $pg = '<h1>Reset Failed</h1>';
 $pg .= '<br>Try again from the Home page Register/Reset button later';
 return $pg;
}
#
function dbreset()
{
 $user = $_SESSION['reset_user'];
 $hash = $_SESSION['reset_hash'];
 $email = $_SESSION['reset_email'];

 $pass = getparam('pass', true);
 $pass2 = getparam('pass2', true);
 $twofa = getparam('2fa', true);

 if (nuem($pass) || nuem($pass2))
	return allow_reset('Enter both passwords');

 if ($pass2 != $pass)
	return allow_reset("Passwords don't match");

 if (safepass($pass) !== true)
	return allow_reset('Password is unsafe');

 $ans = getAtts($user, 'KReset.str,KReset.dateexp');
 if ($ans['STATUS'] != 'ok')
	return resetfail();

 if (!isset($ans['KReset.dateexp']) || $ans['KReset.dateexp'] == 'Y')
	return resetfail();

 if (!isset($ans['KReset.str']) || $ans['KReset.str'] != $hash)
	return resetfail();

 $emailinfo = getOpts($user, emailOptList());
 if ($emailinfo['STATUS'] != 'ok')
	syserror();

 $ans = resetPass($user, $pass, $twofa);
 if ($ans['STATUS'] != 'ok')
	return resetfail();

 unset($_SESSION['reset_user']);
 unset($_SESSION['reset_hash']);
 unset($_SESSION['reset_email']);

 $ans = expAtts($user, 'KReset');

 $ok = passWasReset($email, zeip(), $emailinfo);

 return yok();
}
#
function doreset($data, $u)
{
 // Slow this right down
 usleep(500000);

 if (isset($_SESSION['reset_user'])
 &&  isset($_SESSION['reset_hash'])
 &&  isset($_SESSION['reset_email']))
	return dbreset();

 $code = getparam('code', true);
 if (nuem($code))
	return resetfail();

 $codes = explode('_', $code, 2);

 if (sizeof($codes) != 2)
	return resetfail();

 $userhex = $codes[0];

 if (strlen($userhex) == 0 || strlen($userhex) % 2)
	return resetfail();

 $user = loginStr(pack("H*" , $userhex));

 $hash = preg_replace('/[^A-Fa-f0-9]/', '', $codes[1]);

 if (!nuem($user) && !nuem($hash))
 {
	$ans = getAtts($user, 'KReset.str,KReset.dateexp');
	if ($ans['STATUS'] != 'ok')
		return resetfail();

	if (!isset($ans['KReset.dateexp']) || $ans['KReset.dateexp'] == 'Y')
		return resetfail();

	if (!isset($ans['KReset.str']) || $ans['KReset.str'] != $hash)
		return resetfail();

	$ans = userSettings($user);
	if ($ans['STATUS'] != 'ok')
		return resetfail();

	if (!isset($ans['email']))
		return resetfail();

	$email = $ans['email'];

	$_SESSION['reset_user'] = $user;
	$_SESSION['reset_hash'] = $hash;
	$_SESSION['reset_email'] = $email;

	return allow_reset(null);
 }
 return resetfail();
}
#
function show_reset($info, $page, $menu, $name, $u)
{
 gopage($info, array(), 'doreset', $page, $menu, $name, $u, true, true, false);
}
#
?>
