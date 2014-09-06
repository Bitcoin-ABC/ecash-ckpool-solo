<?php
#
include_once('socket.php');
#
function doreg($data, $u)
{
 if (isset($data['user']))
	$user = htmlspecialchars($data['user']);
 else
	$user = '';

 if (isset($data['mail']))
	$mail = htmlspecialchars($data['mail']);
 else
	$mail = '';

 $pg = '<h1>Register</h1>';
 if (isset($data['error']))
	$pg .= "<br><b>".$data['error']." - please try again</b><br><br>";
 $pg .= makeForm('');
 $pg .= "
<table>
<tr><td class=dr>Username:</td>
 <td class=dl><input name=user value=\"$user\"></td></tr>
<tr><td class=dr>Email:</td>
 <td class=dl><input name=mail value=\"$mail\"></td></tr>
<tr><td class=dr>Password:</td>
 <td class=dl><input type=password name=pass></td></tr>
<tr><td class=dr>Retype Password:</td>
 <td class=dl><input type=password name=pass2></td></tr>
<tr><td>&nbsp;</td>
 <td class=dl><input type=submit name=Register value=Register></td></tr>
<tr><td colspan=2 class=dc><br><font size=-1>All fields are required</font></td></tr>
</table>
</form>";

 return $pg;
}
#
function doreg2($data)
{
 if (isset($data['user']))
	$user = htmlspecialchars($data['user']);
 else
	$user = '';

 $pg = '<h1>Registered</h1>';
// $pg .= '<br>You will receive an email shortly to verify your account';
 $pg .= '<br>Your account is registered and ready to mine.';
 $pg .= '<br>Choose your own worker names in cgminer.';
 $pg .= '<br>Worker names must start with your username like';
 $pg .= ": <span class=hil>${user}_</span> or <span class=hil>${user}.</span>";
 return $pg;
}
#
function show_reg($page, $menu, $name, $u)
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
	if (safepass($pass) !== true)
	{
		$ok = false;
		$data['error'] = "Password is unsafe - requires 6 or more characters, including<br>" .
				 "at least one of each uppercase, lowercase and digits, but not Tab";
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
		gopage($data, 'doreg2', $page, $menu, $name, $u, true, true, false);
	else
		$data['error'] = "Invalid username, password or email address";
 }

 gopage($data, 'doreg', $page, $menu, $name, $u, true, true, false);
}
#
?>
