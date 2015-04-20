<?php
#
function uset($data, $user, $api, $err)
{
 $pg = '<h1>User Settings</h1>';

 if ($err != '')
	$pg .= "<span class=err>$err<br><br></span>";

 $pg .= '<table cellpadding=20 cellspacing=0 border=1>';
 $pg .= '<tr class=dc><td><span class=nb>';
 $pg .= "<input type=checkbox id=minicb onclick='md(this)'>";
 $pg .= 'mini header</span></td></tr>';
 $pg .= '<tr class=dc><td><center>';

 $pg .= makeForm('userset');
 $pg .= '<table cellpadding=5 cellspacing=0 border=0>';
 $pg .= '<tr class=dc><td>';
 if ($api === false)
	$pg .= "You don't have an API Key setup yet";
 else
 {
	$pg .= 'Your current API Key is:';
	$pg .= '</td></tr><tr class=dc><td>';
	$pg .= "<span class=hil>$api</span>";
 }
 $pg .= '</td></tr><tr class=dc><td>';
 $pg .= 'Click to generate a new API key';
 $pg .= ": <input type=submit name=Change value='API Key'>";
 $pg .= '</td></tr>';
 if ($api !== false)
 {
	$pg .= '<tr class=dc><td>&nbsp;</td></tr>';
	$pg .= '<tr class=dc><td>You can access the API via:';
	$pg .= '</td></tr><tr class=dc><td>';
	$pg .= "<span class=hil>/index.php?k=api&username=";
	$pg .= htmlspecialchars(urlencode($user));
	$pg .= "&api=$api&json=y</span><br>";
	$pg .= '</td></tr>';
	$pg .= '<tr class=dc><td>You can get your workers via:';
	$pg .= '</td></tr><tr class=dc><td>';
	$pg .= "<span class=hil>/index.php?k=api&username=";
	$pg .= htmlspecialchars(urlencode($user));
	$pg .= "&api=$api&json=y&work=y</span><br>";
	$pg .= '</td></tr>';
 }
 $pg .= '</table></form>';

 $pg .= '</center></td></tr>';
 $pg .= '</table>';

 return $pg;
}
#
function douserset($data, $user)
{
 $err = '';
 $chg = getparam('Change', false);
 $api = false;
 switch ($chg)
 {
  case 'API Key':
	$ans = getAtts($user, 'KAPIKey.str,KAPIKey.dateexp');
	if ($ans['STATUS'] != 'ok')
		dbdown(); // Should be no other reason?
	if (isset($ans['KAPIKey.dateexp']) && $ans['KAPIKey.dateexp'] == 'N')
	{
		$err = 'You can only change it once a day';
		if (isset($ans['KAPIKey.str']))
			$api = $ans['KAPIKey.str'];
	}
	else
	{
		$ran = $ans['STAMP'].$user.rand(100000000,999999999);
		$api = hash('md4', $ran);

		$day = 60 * 60 * 24;
		$ans = setAtts($user, array('ua_KAPIKey.str' => $api,
						'ua_KAPIKey.date' => "now+$day"));
		if ($ans['STATUS'] != 'ok')
			syserror();

	}
	break;
 }
 if ($api === false)
 {
	$ans = getAtts($user, 'KAPIKey.str');
	if ($ans['STATUS'] != 'ok')
		dbdown(); // Should be no other reason?
	if (isset($ans['KAPIKey.str']))
		$api = $ans['KAPIKey.str'];
 }
 $pg = uset($data, $user, $api, $err);
 return $pg;
}
#
function show_userset($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'douserset', $page, $menu, $name, $user);
}
#
?>
