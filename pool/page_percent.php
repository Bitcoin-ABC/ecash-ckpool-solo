<?php
#
function pertitle($data, $user)
{
 $pg  = '<tr class=title>';
 $pg .= '<td class=dl>Address</td>';
 $pg .= '<td class=dl>ID</td>';
 $pg .= '<td class=dr>Shares</td>';
 $pg .= '<td class=dr>Diff</td>';
 $pg .= '<td class=dr>Invalid</td>';
 $pg .= '<td class=dr>Block %</td>';
 $pg .= '<td class=dr>Hash Rate</td>';
 $pg .= '<td class=dr>Ratio</td>';
 $pg .= '<td class=dr>Addr %</td>';
 $pg .= "</tr>\n";
 return $pg;
}
#
function perhashorder($a, $b)
{
 return $b['payratio'] - $a['payratio'];
}
#
function peruser($data, $user, &$offset, &$totshare, &$totdiff,
			&$totinvalid, &$totrate, &$blockacc,
			&$blockreward, $srt = false)
{
 $ans = getPercents($user);

 $pg = '';
 if ($ans['STATUS'] == 'ok')
 {
	if (isset($ans['blockacc']))
		$blockacc = $ans['blockacc'];
	if (isset($ans['blockreward']))
		$blockreward = $ans['blockreward'];
	$all = array();
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		$all[] = array('payaddress' => $ans['payaddress:'.$i],
				'payratio' => $ans['payratio:'.$i],
				'paypercent' => $ans['paypercent:'.$i],
				'payname' => $ans['payname:'.$i],
				'p_shareacc' => $ans['p_shareacc:'.$i],
				'p_diffacc' => $ans['p_diffacc:'.$i],
				'p_diffinv' => $ans['p_diffinv:'.$i],
				'p_uhr' => $ans['p_hashrate5m:'.$i]);
	}

	if ($srt)
		usort($all, 'perhashorder');

	for ($i = 0; $i < $count; $i++)
	{
		if ((($offset) % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.$all[$i]['payaddress'].'</td>';
		$pg .= '<td class=dl>'.$all[$i]['payname'].'</td>';

		$shareacc = number_format($all[$i]['p_shareacc'], 0);
		$totshare += $all[$i]['p_shareacc'];
		$diffacc = number_format($all[$i]['p_diffacc'], 0);
		$totdiff += $all[$i]['p_diffacc'];
		$pg .= "<td class=dr>$shareacc</td>";
		$pg .= "<td class=dr>$diffacc</td>";

		$dtot = $all[$i]['p_diffacc'] + $all[$i]['p_diffinv'];
		if ($dtot > 0)
			$rej = number_format(100.0 * $all[$i]['p_diffinv'] / $dtot, 3);
		else
			$rej = '0';
		$totinvalid +=  $all[$i]['p_diffinv'];

		$pg .= "<td class=dr>$rej%</td>";

		if ($blockacc <= 0)
			$blkpct = '&nbsp;';
		else
			$blkpct = number_format(100.0 * $all[$i]['p_diffacc'] / $blockacc, 3) . '%';

		$pg .= "<td class=dr>$blkpct</td>";

		$uhr = $all[$i]['p_uhr'];
		if ($uhr == '?')
			$uhr = '?GHs';
		else
		{
			$totrate += $uhr;
			$uhr = dsprate($uhr);
		}
		$pg .= "<td class=dr>$uhr</td>";

		$pg .= '<td class=dr>'.$all[$i]['payratio'].'</td>';
		$paypct = number_format($all[$i]['paypercent'], 3);
		$pg .= "<td class=dr>$paypct%</td>";

		$pg .= "</tr>\n";

		$offset++;
	}
 }
 return $pg;
}
#
function pertotal($offset, $totshare, $totdiff, $totinvalid, $totrate, $blockacc, $blockreward)
{
 $pg = '';
 $totrate = dsprate($totrate);
 if (($offset % 2) == 0)
	$row = 'even';
 else
	$row = 'odd';
 $pg .= "<tr class=$row><td class=dl>Total:</td>";
 $pg .= "<td class=dl>&nbsp;</td>";
 $shareacc = number_format($totshare, 0);
 $pg .= "<td class=dr>$shareacc</td>";
 $diffacc = number_format($totdiff, 0);
 $pg .= "<td class=dr>$diffacc</td>";
 $dtot = $totdiff + $totinvalid;
 if ($dtot > 0)
	$rej = number_format(100.0 * $totinvalid / $dtot, 3);
 else
	$rej = '0';
 $pg .= "<td class=dr>$rej%</td>";
 if ($blockacc <= 0)
	$blkpct = '&nbsp;';
 else
	$blkpct = number_format(100.0 * $totdiff / $blockacc, 3) . '%';
 $pg .= "<td class=dr>$blkpct</td>";
 $pg .= "<td class=dr>$totrate</td>";
 $pg .= "</td><td colspan=2 class=dl></td></tr>\n";
 return $pg;
}
#
function dopercent($data, $user)
{
 $pg = '<h1>Address Percents</h1>';

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";

 $totshare = 0;
 $totdiff = 0;
 $totinvalid = 0;
 $totrate = 0;
 $offset = 0;
 $blockacc = 0;
 $blockreward = 0;

 $pg .= pertitle($data, $user);
 $pg .= peruser($data, $user, $offset, $totshare, $totdiff, $totinvalid,
			$totrate, $blockacc, $blockreward, true);
 $pg .= pertotal($offset, $totshare, $totdiff, $totinvalid, $totrate,
			$blockacc, $blockreward);

 if ($blockacc > 0 && $blockreward > 0)
 {
	$btc = btcfmt($totdiff / $blockacc * $blockreward);
	$pg .= '<tr><td colspan=9 class=dc>';
	$pg .= "<br>Payout est if block found at 100%: ~$btc BTC";
	$pg .= '</td></tr>';
 }

 $pg .= "</table>\n";

 return $pg;
}
#
function show_percent($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dopercent', $page, $menu, $name, $user);
}
#
?>
