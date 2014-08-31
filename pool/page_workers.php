<?php
#
function doworker($data, $user)
{
 $pg = '<h1>Workers</h1>';

 $rep = getWorkers($user);
 $ans = repDecode($rep);

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dl>Worker Name</td>";
// $pg .= "<td class=dr>Difficulty</td>";
// $pg .= "<td class=dc>Idle Notifications</td>";
// $pg .= "<td class=dr>Idle Notification Time</td>";
 $pg .= "<td class=dr>Work Diff</td>";
 $pg .= "<td class=dr>Last Share</td>";
 $pg .= "<td class=dr>Hash Rate</td>";
 $pg .= "</tr>\n";
 if ($ans['STATUS'] == 'ok')
 {
	$thr = 0;
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.$ans['workername'.$i].'</td>';
/*
		$pg .= '<td class=dr>'.$ans['difficultydefault'.$i].'</td>';
		$nots = $ans['idlenotificationenabled'.$i];
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
		$pg .= '<td class=dr>'.$ans['idlenotificationtime'.$i].'</td>';
*/
		if ($ans['w_lastdiff'.$i] > 0)
			$ld = difffmt($ans['w_lastdiff'.$i]);
		else
			$ld = '&nbsp;';
		$pg .= "<td class=dr>$ld</td>";
		$lst = $ans['STAMP'] - $ans['w_lastshare'.$i];
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
		if ($ans['w_elapsed'.$i] > 3600)
			$uhr = $ans['w_hashrate1hr'.$i];
		else
			$uhr = $ans['w_hashrate5m'.$i];
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
 $pg .= "<tr class=$row><td colspan=3 class=dl></td><td class=dr>$thr</td></tr>\n";
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
function show_workers($menu, $name, $user)
{
 gopage(NULL, 'doworkers', $menu, $name, $user);
}
#
?>
