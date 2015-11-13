<?php
#
include_once('socket.php');
include_once('email.php');
#
function doregres($data, $u)
{
 if (isset($data['data']['user']))
	$user = htmlspecialchars($data['data']['user']);
 else
	$user = '';

 if (isset($data['data']['mail']))
	$mail = htmlspecialchars($data['data']['mail']);
 else
	$mail = '';

 $pg = makeForm('')."<br>
<table cellpadding=0 cellspacing=0 border=0><tr>
<td>User:</td><td><input type=text name=User size=10 value=''></td>
<td>&nbsp;Pass:</td><td><input type=password name=Pass size=10 value=''></td>
<td>&nbsp;<input type=submit name=Login value=Login></td>
</tr></table></form>";

 $pg .= '<br><h1>or choose one:</h1>';

 $pg .= '<table cellpadding=5 cellspacing=0 border=1><tr><td class=dc>';

 $pg .= '<h1>Login</h1>';
 if (isset($data['data']['error']))
	$pg .= "<br><b>".$data['data']['error']." - please try again</b><br><br>";
 $pg .= makeForm('');
 $pg .= "
<table>
<tr><td class=dr>Username:</td>
 <td class=dl><input name=User value=''></td></tr>
<tr><td class=dr>Password:</td>
 <td class=dl><input type=password name=Pass value=''></td></tr>
<tr><td class=dr><span class=st1>*</span>2nd Authentication:</td>
 <td class=dl><input type=password name=2fa size=10></td></tr>
<tr><td colspan=2 class=dc><font size=-1><span class=st1>*</span>
 Leave blank if you haven't enabled it</font></td></tr>
<tr><td>&nbsp;</td>
 <td class=dl><input type=submit name=Login value=Login></td></tr>
</table>
</form>";

 $pg.= '</td></tr><tr><td class=dc>';

 $pg .= '<h1>Register</h1>';
 if (isset($data['data']['error']))
	$pg .= "<br><b>".$data['data']['error']." - please try again</b><br><br>";
 $pg .= makeForm('');
 $pg .= "
<table>
<tr><td class=dr>Username:</td>
 <td class=dl><input name=user value=\"$user\"></td></tr>
<tr><td class=dr>Email:</td>
 <td class=dl><input name=mail value=\"$mail\"></td></tr>
<tr><td class=dr>Password:</td>
 <td class=dl><input type=password name=pass value=''></td></tr>
<tr><td class=dr>Retype Password:</td>
 <td class=dl><input type=password name=pass2 value=''></td></tr>
<tr><td>&nbsp;</td>
 <td class=dl><input type=submit name=Register value=Register></td></tr>
<tr><td colspan=2 class=dc><br><font size=-1><span class=st1>*</span>
 All fields are required<br>Your Username can't be a BTC address</font></td></tr>
<tr><td colspan=2 class=dc><font size=-1><br>Note: your username is upper/lowercase sensitive,<br>
and you must also have upper/lowercase correct on all your miners<br><br>" . passrequires() . "</font></td></tr>
</table>
</form>";

 $pg.= '</td></tr><tr><td class=dc>';

 $pg .= '<h1>Password Reset</h1>';
 $pg .= makeForm('');
 $pg .= "
<table>
<tr><td class=dr>Username:</td>
 <td class=dl><input name=user value=\"$user\"></td></tr>
<tr><td class=dr>Email:</td>
 <td class=dl><input name=mail value=''></td></tr>
<tr><td>&nbsp;</td>
 <td class=dl><input type=submit name=Reset value=Reset></td></tr>
<tr><td colspan=2 class=dc><br><font size=-1>
If you enter the details correctly,<br>
an Email will be sent to you to let you reset your password</font></td></tr>
</table>
</form>";

 $pg .= '</td></tr></table>';

 return $pg;
}
#
function doreg2($data)
{
 if (isset($data['data']['user']))
	$user = htmlspecialchars($data['data']['user']);
 else
	$user = '';

 $pg = '<h1>Registered</h1>';
// $pg .= '<br>You will receive an email shortly to verify your account';
 $pg .= '<br>Your account is registered and ready to mine.';
 $pg .= '<br>Choose your own worker names in cgminer.';
 $pg .= '<br>Worker names must start with your username and a dot or an underscore';
 $pg .= "<br>e.g. <span class=hil>${user}_worker1</span> or <span class=hil>${user}.worker7</span>";
 return $pg;
}
#
function try_reg($info, $page, $menu, $name, $u)
{
 $user = getparam('user', false);
 $mail = trim(getparam('mail', false));
 $pass = getparam('pass', false);
 $pass2 = getparam('pass2', false);

 $data = array();

 if (nuem($user))
	$data['user'] = '';
 else
	$data['user'] = $user;

 if (nuem($mail))
	$data['mail'] = '';
 else
	$data['mail'] = $mail;

 $ok = true;
 if (nuem($user) || nuem($mail) || nuem($pass) || nuem($pass2))
	$ok = false;
 else
 {
	if (stripos($mail, 'hotmail') !== false)
	{
		$ok = false;
		$data['error'] = "hotmail not allowed";
	}

	if (safepass($pass) !== true)
	{
		$ok = false;
		$data['error'] = "Password is unsafe";
	}
	elseif ($pass2 != $pass)
	{
		$ok = false;
		$data['error'] = "Passwords don't match";
	}

	$orig = $user;
	$user = loginStr($orig);
	if ($user != $orig)
	{
		$ok = false;
		$data['error'] = "Username cannot include '.', '_', '/' or Tab";
		$data['user'] = $user;
	}
 }

 if ($ok === true)
 {
	$ans = userReg($user, $mail, $pass);
	if ($ans['STATUS'] == 'ok')
		gopage($info, $data, 'doreg2', $page, $menu, $name, $u, true, true, false);
	else
		$data['error'] = "Invalid username, password or email address";
 }

 gopage($info, $data, 'doregres', $page, $menu, $name, $u, true, true, false);
}
#
function doreset2($data)
{
 $user = $data['data']['user'];
 $email = $data['data']['email'];

 $emailinfo = getOpts($user, emailOptList());
 if ($emailinfo['STATUS'] != 'ok')
	syserror();

 $ans = getAtts($user, 'KLastReset.dateexp');
 if ($ans['STATUS'] != 'ok')
	syserror();

 // If the last attempt hasn't expired don't do anything but show a fake msg
 if (!isset($ans['KLastReset.dateexp']) || $ans['KLastReset.dateexp'] == 'Y')
 {
	// This line $code = isn't an attempt at security -
	// it's simply to ensure the username is readable when we get it back
	$code = bin2hex($data['data']['user']). '_';

	// A code that's large enough to not be worth guessing
	$ran = $ans['STAMP'].$user.$email.rand(100000000,999999999);
	$hash = hash('md4', $ran);

	$ans = setAtts($user, array('ua_KReset.str' => $hash,
					'ua_KReset.date' => 'now+3600',
					'ua_LastReset.date' => 'now+3600'));
	if ($ans['STATUS'] != 'ok')
		syserror();

	$ok = passReset($email, $code.$hash, zeip(), $emailinfo);
	if ($ok === false)
		syserror();
 }

 $pg = '<h1>Reset Sent</h1>';
 $pg .= '<br>An Email has been sent that will allow you to';
 $pg .= '<br>reset your password.';
 $pg .= '<br>If you got your username or email address wrong,';
 $pg .= '<br>you wont get the email.';
 return $pg;
}
#
function try_reset($info, $page, $menu, $name, $u)
{
 $user = getparam('user', false);
 $mail = trim(getparam('mail', false));

 $data = array();

 if (!nuem($user))
	$user = loginStr($user);

 if (!nuem($user) && !nuem($mail))
 {
	$ans = userSettings($user);
	if ($ans['STATUS'] == 'ok' && isset($ans['email']) && $ans['email'] == $mail)
	{
		$data = array('user' => $user, 'email' => $mail);

		gopage($info, $data, 'doreset2', $page, $menu, $name, $u, true, true, false);
	}
 }

 gopage($info, $data, 'doregres', $page, $menu, $name, $u, true, true, false);
}
#
function show_reg($info, $page, $menu, $name, $u)
{
 // Slow this right down
 usleep(1000000);

 $reg = getparam('Register', false);
 if ($reg !== NULL)
	try_reg($info, $page, $menu, $name, $u);
 else
	try_reset($info, $page, $menu, $name, $u);
}
#
?>
