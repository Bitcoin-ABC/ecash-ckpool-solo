<?php
#
function doworker($data, $user)
{
 $pg = '<h1>Workers</h1>';

 $ans = getWorkers($user);

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dl>Worker Name</td>";
// $pg .= "<td class=dr>Difficulty</td>";
// $pg .= "<td class=dc>Idle Notifications</td>";
// $pg .= "<td class=dr>Idle Notification Time</td>";
 $pg .= "<td class=dr>Work Diff</td>";
 $pg .= "<td class=dr>Last Share</td>";
 $pg .= "<td class=dr>Shares</td>";
 $pg .= "<td class=dr>Diff</td>";
 $pg .= "<td class=dr>Invalid</td>";
 $pg .= "<td class=dr>Hash Rate</td>";
 $pg .= "</tr>\n";
 $tsh = 0;
 $tdif = 0;
 $tinv = 0;
 $thr = 0;
 $i = 0;
 if ($ans['STATUS'] == 'ok')
 {
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.$ans['workername:'.$i].'</td>';
/*
		$pg .= '<td class=dr>'.$ans['difficultydefault:'.$i].'</td>';
		$nots = $ans['idlenotificationenabled:'.$i];
		switch ($nots)
		{
		case 'Y':
		case 'y':
			$nots = 'Y';
			break;
		default:
			$nots = 'N';
		}
		$pg .= '<td class=dc>'.$nots.'</td>';
		$pg .= '<td class=dr>'.$ans['idlenotificationtime:'.$i].'</td>';
*/
		if ($ans['w_lastdiff:'.$i] > 0)
			$ld = difffmt($ans['w_lastdiff:'.$i]);
		else
			$ld = '&nbsp;';
		$pg .= "<td class=dr>$ld</td>";
		$lst = $ans['STAMP'] - $ans['w_lastshare:'.$i];
		if ($lst < 60)
			$lstdes = $lst.'s';
		else
		{
			$lst = round($lst/60);
			if ($lst < 60)
				$lstdes = $lst.'min';
			else
			{
				$lst = round($lst/60);
				if ($lst < 24)
				{
					$lstdes = $lst.'hr';
					if ($lst != 1)
						$lstdes .= 's';
				}
				else
				{
					$lst = round($lst/24);
					if ($lst < 9999)
					{
						$lstdes = $lst.'day';
						if ($lst != 1)
							$lstdes .= 's';
					}
					else
						$lstdes = 'never';
				}
			}
		}
		$pg .= "<td class=dr>$lstdes</td>";

		$shareacc = number_format($ans['w_shareacc:'.$i], 0);
		$tsh += $ans['w_shareacc:'.$i];
		$diffacc = number_format($ans['w_diffacc:'.$i], 0);
		$tdif += $ans['w_diffacc:'.$i];
		$pg .= "<td class=dr>$shareacc</td>";
		$pg .= "<td class=dr>$diffacc</td>";

		$dtot = $ans['w_diffacc:'.$i] + $ans['w_diffinv:'.$i];
		if ($dtot > 0)
			$rej = number_format(100.0 * $ans['w_diffinv:'.$i] / $dtot, 3);
		else
			$rej = '0';
		$tinv +=  $ans['w_diffinv:'.$i];

		$pg .= "<td class=dr>$rej%</td>";

		if ($ans['w_elapsed:'.$i] > 3600)
			$uhr = $ans['w_hashrate1hr:'.$i];
		else
			$uhr = $ans['w_hashrate5m:'.$i];
		if ($uhr == '?')
			$uhr = '?GHs';
		else
		{
			$thr += $uhr;
			$uhr /= 10000000;
			if ($uhr < 0.01)
				$uhr = '0GHs';
			else
			{
				if ($uhr < 100000)
					$uhr = number_format(round($uhr)/100,2).'GHs';
				else
					$uhr = number_format(round($uhr/1000)/100,2).'THs';
			}
		}
		$pg .= "<td class=dr>$uhr</td>";

		$pg .= "</tr>\n";
	}
 }
 $thr /= 10000000;
 if ($thr < 0.01)
	$thr = '0GHs';
 else
 {
	if ($thr < 100000)
		$thr = number_format(round($thr)/100,2).'GHs';
	else
		$thr = number_format(round($thr/1000)/100,2).'THs';
 }
 if (($i % 2) == 0)
	$row = 'even';
 else
	$row = 'odd';
 $pg .= "<tr class=$row><td class=dl>Total:</td><td colspan=2 class=dl></td>";
 $shareacc = number_format($tsh, 0);
 $pg .= "<td class=dr>$shareacc</td>";
 $diffacc = number_format($tdif, 0);
 $pg .= "<td class=dr>$diffacc</td>";
 $dtot = $tdif + $tinv;
 if ($dtot > 0)
	$rej = number_format(100.0 * $tinv / $dtot, 3);
 else
	$rej = '0';
 $pg .= "<td class=dr>$rej%</td>";
 $pg .= "<td class=dr>$thr</td></tr>\n";
 $pg .= "</table>\n";

 return $pg;
}
#
function doworkers($data, $user)
{
 $pg = doworker($data, $user);
 return $pg;
}
#
function show_workers($page, $menu, $name, $user)
{
 gopage(NULL, 'doworkers', $page, $menu, $name, $user);
}
#
?>
