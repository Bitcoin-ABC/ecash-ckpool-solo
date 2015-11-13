<?php
#
function doshifts($data, $user)
{
 $ans = getShifts($user);

 $pg = "Click <a href='#payoutmark'>here</a> to jump to the start of the last payout<br><br>";
 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dl>Shift</td>";
 $pg .= "<td class=dl>Start UTC</td>";
 $pg .= "<td class=dr>Length</td>";
 $pg .= "<td class=dr>Your Diff</td>";
 $pg .= "<td class=dr>Inv Diff</td>";
 $pg .= "<td class=dr>Avg Hs</td>";
 $pg .= "<td class=dr>Shares</td>";
 $pg .= "<td class=dr>Avg Share</td>";
 $pg .= "<td class=dr>Rewards</td>";
 $pg .= "<td class=dr>Rewarded<span class=st1>*</span></td>";
 $pg .= "<td class=dr>PPS%</td>";
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
		$u = '';
		$mark = '';
		if (isset($ans['lastpayoutstart:'.$i])
		&&  $ans['lastpayoutstart:'.$i] != '')
		{
			$u = 'u';
			$mark = '<a name=payoutmark></a>';
		}
		if (($i % 2) == 0)
			$row = "even$u";
		else
			$row = "odd$u";

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
		$pg .= "<td class=dl>$shif$btc$mark</td>";
		$start = $ans['start:'.$i];
		$pg .= '<td class=dl>'.utcd($start, true).'</td>';
		$nd = $ans['end:'.$i];
		$elapsed = $nd - $start;
		$pg .= '<td class=dr>'.howmanyhrs($elapsed).'</td>';
		$diffacc = $ans[$pre.'diffacc:'.$i];
		$pg .= '<td class=dr>'.difffmt($diffacc).'</td>';
		$diffinv = $ans[$pre.'diffinv:'.$i];
		$pg .= '<td class=dr>'.difffmt($diffinv).'</td>';
		$hr = $diffacc * pow(2,32) / $elapsed;
		$pg .= '<td class=dr>'.dsprate($hr).'</td>';
		$shareacc = $ans[$pre.'shareacc:'.$i];
		$pg .= '<td class=dr>'.difffmt($shareacc).'</td>';
		if ($shareacc > 0)
			$avgsh = $diffacc / $shareacc;
		else
			$avgsh = 0;
		$pg .= '<td class=dr>'.number_format($avgsh, 2).'</td>';
		$pg .= '<td class=dr>'.$ans['rewards:'.$i].'</td>';
		$ppsr = (float)$ans['ppsrewarded:'.$i];
		if ($ppsr > 0)
			$ppsd = sprintf('%.5f', $ppsr);
		else
			$ppsd = '0';
		$pg .= "<td class=dr>$ppsd</td>";
		$ppsv = (float)$ans['ppsvalue:'.$i];
		if ($ppsv > 0)
			$pgot = number_format(100.0 * $ppsr / $ppsv, 2).'%';
		else
			$pgot = '?';
		$pg .= "<td class=dr>$pgot</td>";
		$pg .= "</tr>\n";
	}
 }
 $pg .= "</table>\n";
 $pg .= "<span class=st1>*</span> The Rewarded value unit is satoshis per 1diff share<br>";

 return $pg;
}
#
function show_shifts($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doshifts', $page, $menu, $name, $user);
}
#
?>
