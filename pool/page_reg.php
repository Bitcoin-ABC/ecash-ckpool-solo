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
 $pg .= "
<form action=index.php method=POST>
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
function show_reg($menu, $name, $u)
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
	$user = preg_replace('/[\._\/\011]/', '', $orig);
	if ($user != $orig)
	{
		$ok = false;
		$data['error'] = "Username cannot include '.', '_', '/' or Tab";
		$data['user'] = $user;
	}
 }

 if ($ok === true)
 {
	$passhash = myhash($pass);
	$flds = array('username' => $user,
			'emailaddress' => $mail,
			'passwordhash' => $passhash);
	$msg = msgEncode('adduser', 'reg', $flds);
	$rep = sendsockreply('show_reg', $msg);
	if (!$rep)
		dbdown();

	$ans = repDecode($rep);
	if ($ans['STATUS'] == 'ok')
		gopage($data, 'doreg2', $menu, $name, $u, true, true, false);
	else
		$data['error'] = "Invalid details";
 }

 gopage($data, 'doreg', $menu, $name, $u, true, true, false);
}
#
?>
