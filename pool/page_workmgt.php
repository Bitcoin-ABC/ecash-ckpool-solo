<?php
#
function workmgtuser($data, $user, $err)
{
 $pg = '<h1>Worker Management</h1>';

 if ($err != '')
	$pg .= "<span class=err>$err<br><br></span>";

 $ans = getWorkers($user, 'N');

 if ($ans['STATUS'] == 'ok')
 {
	if (isset($ans['oldworkers']) && $ans['oldworkers'] == '0')
		$chk = '';
	else
		$chk = ' checked';
	$pg .= makeForm('workmgt');
	$pg .= '<span>Active workers (7 days)';
	$pg .= "<input type=checkbox name=seven$chk>";
	$pg .= '<input type=submit name=S value=Update>';
	$pg .= '</span></form><br><br>';
 }

 $pg .= makeForm('workmgt');
 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= '<tr class=title>';
 $pg .= '<td class=dl>Worker Name</td>';
 $pg .= '<td class=dr>Minimum Diff</td>';
 $pg .= '</tr>';

 $offset = 0;
 if ($ans['STATUS'] == 'ok')
 {
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if ((($offset) % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";

		$wn = htmlspecialchars($ans['workername:'.$i]);
		$wnv = urlencode($ans['workername:'.$i]);
		$pg .= '<td class=dl>';
		$pg .= "<input type=hidden name='workername:$i' value='$wnv'>";
		$pg .= $wn.'</td>';

		$md = intval($ans['difficultydefault:'.$i]);
		$pg .= '<td class=dr>';
		$pg .= "<input type=text size=6 name='difficultydefault:$i' value='$md'>";
		$pg .= "<input type=submit name=OK value=OK>";
		$pg .= "</td>";

		$pg .= "</tr>\n";

		$offset++;
	}
 }
 $pg .= '<tr><td colspan=2 class=dc><font size=-1><span class=st1>*</span>';
 $pg .= ' A value of 0, less than the pool minimum,<br>';
 $pg .= 'or less than the pool calculated value for you,<br>';
 $pg .= 'will use the pool calculated value</font></td></tr>';
 $pg .= "</table><input type=hidden name=rows value=$count></form>\n";

 return $pg;
}
#
function doworkmgt($data, $user)
{
 $err = '';
 $S = getparam('S', false);
 $chk = getparam('seven', false);
 if ($S == 'Update')
 {
	$settings = array();
	if ($chk == 'on')
		$settings['oldworkers'] = '7';
	else
		$settings['oldworkers'] = '0';
	$ans = workerSet($user, $settings);
	if ($ans['STATUS'] != 'ok')
		$err = $ans['ERROR'];
 }
 else
 {
	$OK = getparam('OK', false);
	$count = getparam('rows', false);
	if ($OK == 'OK' && !nuem($count))
	{
		if ($count > 0 && $count < 9999)
		{
			$settings = array();
			for ($i = 0; $i < $count; $i++)
			{
				$wn = urldecode(getparam('workername:'.$i, false));
				$md = getparam('difficultydefault:'.$i, false);
				if (!nuem($wn) && !nuem($md))
				{
					$settings['workername:'.$i] = $wn;
					$settings['difficultydefault:'.$i] = $md;
				}
			}
			$ans = workerSet($user, $settings);
			if ($ans['STATUS'] != 'ok')
				$err = $ans['ERROR'];
		}
	}
 }

 $pg = workmgtuser($data, $user, $err);

 return $pg;
}
#
function show_workmgt($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doworkmgt', $page, $menu, $name, $user);
}
#
?>
