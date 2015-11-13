<?php
#
function dompayouts($data, $user)
{
 $pg = '<h1>Mining Rewards</h1>';

 $ans = getMPayouts($user);

 $pg .= "The rewards you've earned for each block the pool has found.<br>";
 $pg .= 'See the ';
 $pg .= makeLink('payments');
 $pg .= "Payments</a> page for the payments you've been sent.<br><br>";

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dr>Block</td>";
 $pg .= "<td class=dr>Block UTC</td>";
 $pg .= "<td class=dr>Miner Reward</td>";
 $pg .= "<td class=dr>N Diff</td>";
 $pg .= "<td class=dr>N Range</td>";
 $pg .= "<td class=dr>Pool N Avg</td>";
 $pg .= "<td class=dr>Your %</td>";
 $pg .= "<td class=dr>Your N Diff</td>";
 $pg .= "<td class=dr>Your N Avg</td>";
 $pg .= "<td class=dr>Your BTC</td>";
 $pg .= "</tr>\n";
 if ($ans['STATUS'] == 'ok')
 {
	$totamt = 0;
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dr>'.$ans['height:'.$i].'</td>';
		$pg .= '<td class=dr>'.gmdate('j/M H:i',$ans['blockcreatedate:'.$i]).'</td>';
		$pg .= '<td class=dr>'.btcfmt($ans['minerreward:'.$i]).'</td>';
		$diffused = $ans['diffused:'.$i];
		$pg .= '<td class=dr>'.difffmt($diffused).'</td>';
		$elapsed = $ans['elapsed:'.$i];
		$pg .= '<td class=dr>'.howmanyhrs($elapsed).'</td>';
		$phr = $diffused * pow(2,32) / $elapsed;
		$pg .= '<td class=dr>'.siprefmt($phr).'Hs</td>';
		$diffacc = $ans['diffacc:'.$i];
		$ypct = $diffacc * 100 / $diffused;
		$pg .= '<td class=dr>'.number_format($ypct, 2).'%</td>';
		$pg .= '<td class=dr>'.difffmt($diffacc).'</td>';
		$hr = $diffacc * pow(2,32) / $elapsed;
		$pg .= '<td class=dr>'.dsprate($hr).'</td>';
		$amount = $ans['amount:'.$i];
		$totamt += $amount;
		$pg .= '<td class=dr>'.btcfmt($amount).'</td>';
		$pg .= "</tr>\n";
	}
	if ($count > 1)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dr>Total:</td>';
		$pg .= '<td class=dl colspan=8></td>';
		$pg .= '<td class=dr>'.btcfmt($totamt).'</td>';
		$pg .= "</tr>\n";
	}
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_mpayouts($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dompayouts', $page, $menu, $name, $user);
}
#
?>
