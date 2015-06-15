<?php
#
include_once('email.php');
#
function settings($data, $user, $email, $addr, $err)
{
 $pg = '<h1>Account Settings</h1>';

 if ($err != '')
	$pg .= "<span class=err>$err<br><br></span>";

 $pg .= '<table cellpadding=20 cellspacing=0 border=1>';
 $pg .= '<tr class=dc><td><center>';

 $_SESSION['old_set_email'] = $email;

 $pg .= makeForm('settings');
 $pg .= '<table cellpadding=5 cellspacing=0 border=0>';
 $pg .= '<tr class=dc><td class=dr colspan=2>';
 $pg .= 'To change your email, enter a new email address and your password';
 $pg .= '</td></tr>';
 $pg .= '<tr class=dc><td class=dr>';
 $pg .= 'EMail:';
 $pg .= '</td><td class=dl>';
 $pg .= "<input type=text name=email value='$email' size=20>";
 $pg .= '</td></tr>';
 $pg .= '<tr class=dc><td class=dr>';
 $pg .= 'Password:';
 $pg .= '</td><td class=dl>';
 $pg .= '<input type=password name=pass size=20>';
 $pg .= '</td></tr>';
 $pg .= '<tr class=dc><td class=dr colspan=2>';
 $pg .= 'Change: <input type=submit name=Change value=EMail>';
 $pg .= '</td></tr>';
 $pg .= '</table></form>';

 $pg .= '</center></td></tr>';
 $pg .= '<tr class=dc><td><center>';

 if (!isset($data['info']['u_multiaddr']))
 {
  $pg .= makeForm('settings');
  $pg .= '<table cellpadding=5 cellspacing=0 border=0>';
  $pg .= '<tr class=dc><td class=dr colspan=2>';
  $pg .= 'To change your payout address, enter a new address and your password';
  $pg .= '</td></tr>';
  $pg .= '<tr class=dc><td class=dr>';
  $pg .= 'BTC Address:';
  $pg .= '</td><td class=dl>';
  $pg .= "<input type=text name=baddr value='$addr' size=42>";
  $pg .= '</td></tr>';
  $pg .= '<tr class=dc><td class=dr>';
  $pg .= 'Password:';
  $pg .= '</td><td class=dl>';
  $pg .= '<input type=password name=pass size=20>';
  $pg .= '</td></tr>';
  $pg .= '<tr class=dc><td class=dr colspan=2>';
  $pg .= 'Change: <input type=submit name=Change value=Address>';
  $pg .= '</td></tr>';
  $pg .= '</table></form>';

  $pg .= '</center></td></tr>';
  $pg .= '<tr class=dc><td><center>';
 }

 $pg .= makeForm('settings');
 $pg .= '<table cellpadding=5 cellspacing=0 border=0>';
 $pg .= '<tr class=dc><td class=dr colspan=2>';
 $pg .= 'To change your password, enter your old password and new password twice';
 $pg .= '</td></tr>';
 $pg .= '<tr class=dc><td class=dr nowrap>';
 $pg .= 'Old Password:';
 $pg .= '</td><td class=dl>';
 $pg .= "<input type=password name=oldpass size=20>";
 $pg .= '</td></tr>';
 $pg .= '<tr class=dc><td class=dr nowrap>';
 $pg .= 'New Password:';
 $pg .= '</td><td class=dl>';
 $pg .= '<input type=password name=pass1 size=20>';
 $pg .= '</td></tr>';
 $pg .= '<tr class=dc><td class=dr nowrap>';
 $pg .= 'New Password again:';
 $pg .= '</td><td class=dl>';
 $pg .= '<input type=password name=pass2 size=20>';
 $pg .= '</td></tr>';
 $pg .= '<tr class=dc><td class=dr colspan=2>';
 $pg .= 'Change: <input type=submit name=Change value=Password>';
 $pg .= '</td></tr>';
 $pg .= '</table></form>';

 $pg .= '</center></td></tr>';
 $pg .= '</table>';

 return $pg;
}
#
function dosettings($data, $user)
{
 $err = '';
 $chg = getparam('Change', false);
 $check = false;
 switch ($chg)
 {
  case 'EMail':
	$email = getparam('email', false);
	$pass = getparam('pass', false);
	$ans = userSettings($user, $email, null, $pass);
	$err = 'EMail changed';
	$check = true;
	break;
  case 'Address':
	if (!isset($data['info']['u_multiaddr']))
	{
		$addr = getparam('baddr', false);
		$addrarr = array(array('addr' => $addr));
		$pass = getparam('pass', false);
		$ans = userSettings($user, null, $addrarr, $pass);
		$err = 'Payout address changed';
		$check = true;
	}
	break;
  case 'Password':
	$oldpass = getparam('oldpass', false);
	$pass1 = getparam('pass1', false);
	$pass2 = getparam('pass2', false);
	if (!safepass($pass1))
	{
		$err = "Password is unsafe - requires 6 or more characters, including<br>" .
			"at least one of each uppercase, lowercase and digits, but not Tab";
	}
	elseif ($pass1 != $pass2)
		$err = "Passwords don't match";
	else
	{
		$ans = setPass($user, $oldpass, $pass1);
		$err = 'Password changed';
		$check = true;
	}
	break;
 }
 $doemail = false;
 if ($check === true)
 {
	if ($ans['STATUS'] != 'ok')
	{
		$err = $ans['STATUS'];
		if ($ans['ERROR'] != '')
			$err .= ': '.$ans['ERROR'];
	}
	else
		$doemail = true;
 }
 $ans = userSettings($user);
 if ($ans['STATUS'] != 'ok')
	dbdown(); // Should be no other reason?
 if (isset($ans['email']))
	$email = $ans['email'];
 else
	$email = '';
 // Use the first one - updating will expire all others
 if (isset($ans['rows']) and $ans['rows'] > 0)
	$addr = $ans['addr:0'];
 else
	$addr = '';

 if ($doemail)
 {
	if ($email == '')
	{
		if ($err != '')
			$err .= '<br>';
		$err .= 'An error occurred, check your details below';
		goto iroiroattanoyo;
	}

	$emailinfo = getOpts($user, emailOptList());
	if ($emailinfo['STATUS'] != 'ok')
	{
		if ($err != '')
			$err .= '<br>';
		$err .= 'An error occurred, check your details below';
		goto iroiroattanoyo;
	}

	switch ($chg)
	{
	  case 'EMail':
		if (isset($_SESSION['old_set_email']))
			$old = $_SESSION['old_set_email'];
		else
			$old = null;
		emailAddressChanged($email, zeip(), $emailinfo, $old);
		break;
	  case 'Address':
		payoutAddressChanged($email, zeip(), $emailinfo);
		break;
	  case 'Password':
		passChanged($email, zeip(), $emailinfo);
		break;
	}
 }
iroiroattanoyo:
 $pg = settings($data, $user, $email, $addr, $err);
 return $pg;
}
#
function show_settings($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dosettings', $page, $menu, $name, $user);
}
#
?>
