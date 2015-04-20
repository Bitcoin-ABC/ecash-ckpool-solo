<?php
#
function doshifts($data, $user)
{
 $ans = getShifts($user);

 $pg = "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dl>Shift</td>";
 $pg .= "<td class=dl>Start</td>";
 $pg .= "<td class=dr>Length</td>";
 $pg .= "<td class=dr>Your Diff</td>";
 $pg .= "<td class=dr>Avg Hs</td>";
 $pg .= "<td class=dr>Shares</td>";
 $pg .= "<td class=dr>Avg Share</td>";
 $pg .= "</tr>\n";

 if (($ans['STATUS'] != 'ok') || !isset($ans['prefix_all']))
	$pg = '<h1>Shifts</h1>'.$pg;
 else
 {
	$pre = $ans['prefix_all'];

	$count = $ans['rows'];
	$pg = '<h1>Last '.($count+1).' Shifts</h1>'.$pg;
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$shifname = $ans['shift:'.$i];
		$shif = preg_replace(array('/^.* to /','/^.*fin: /'), '', $shifname);
		$ablock = false;
		if (preg_match('/to.*Block.* fin/', $shifname) == 1)
			$ablock = true;
		else
		{
			$shifex = $ans['endmarkextra:'.$i];
			if (preg_match('/Block .* fin/', $shifex) == 1)
				$ablock = true;
		}
		if ($ablock === true)
			$btc = ' <img src=/BTCSym.png border=0>';
		else
			$btc = '';
		$pg .= "<td class=dl>$shif$btc</td>";
		$start = $ans['start:'.$i];
		$pg .= '<td class=dl>'.utcd($start).'</td>';
		$nd = $ans['end:'.$i];
		$elapsed = $nd - $start;
		$pg .= '<td class=dr>'.howmanyhrs($elapsed).'</td>';
		$diffacc = $ans[$pre.'diffacc:'.$i];
		$pg .= '<td class=dr>'.difffmt($diffacc).'</td>';
		$hr = $diffacc * pow(2,32) / $elapsed;
		$pg .= '<td class=dr>'.dsprate($hr).'</td>';
		$shareacc = $ans[$pre.'shareacc:'.$i];
		$pg .= '<td class=dr>'.difffmt($shareacc).'</td>';
		if ($shareacc > 0)
			$avgsh = $diffacc / $shareacc;
		else
			$avgsh = 0;
		$pg .= '<td class=dr>'.number_format($avgsh, 2).'</td>';
		$pg .= "</tr>\n";
	}
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_shifts($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doshifts', $page, $menu, $name, $user);
}
#
?>
