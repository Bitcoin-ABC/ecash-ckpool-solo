<?php
#
function worktitle($data, $user)
{
 $pg  = '<tr class=title>';
 $pg .= '<td class=dl>Worker Name</td>';
 $pg .= '<td class=dr>Work Diff</td>';
 $pg .= '<td class=dr>Last Share</td>';
 $pg .= '<td class=dr>Shares</td>';
 $pg .= '<td class=dr>Diff</td>';
 $pg .= '<td class=dr>Invalid</td>';
 $pg .= '<td class=dr>Block %</td>';
 $pg .= '<td class=dr>Hash Rate</td>';
 $pg .= "</tr>\n";
 return $pg;
}
#
function workuser($data, $user, &$offset, &$totshare, &$totdiff,
			&$totinvalid, &$totrate, &$blockacc,
			&$blockreward, $old = false)
{
 $ans = getWorkers($user);

 $pg = '';
 if ($ans['STATUS'] == 'ok')
 {
	if (isset($ans['blockacc']))
		$blockacc = $ans['blockacc'];
	if (isset($ans['blockreward']))
		$blockreward = $ans['blockreward'];
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		$lst = $ans['STAMP'] - $ans['w_lastshare:'.$i];
		if ($old !== false && $lst > $old)
			continue;

		if ((($offset) % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.$ans['workername:'.$i].'</td>';
		if ($ans['w_lastdiff:'.$i] > 0)
			$ld = difffmt($ans['w_lastdiff:'.$i]);
		else
			$ld = '&nbsp;';
		$pg .= "<td class=dr>$ld</td>";

		$pg .= '<td class=dr>'.howlongago($lst).'</td>';

		$shareacc = number_format($ans['w_shareacc:'.$i], 0);
		$totshare += $ans['w_shareacc:'.$i];
		$diffacc = number_format($ans['w_diffacc:'.$i], 0);
		$totdiff += $ans['w_diffacc:'.$i];
		$pg .= "<td class=dr>$shareacc</td>";
		$pg .= "<td class=dr>$diffacc</td>";

		$dtot = $ans['w_diffacc:'.$i] + $ans['w_diffinv:'.$i];
		if ($dtot > 0)
			$rej = number_format(100.0 * $ans['w_diffinv:'.$i] / $dtot, 3);
		else
			$rej = '0';
		$totinvalid +=  $ans['w_diffinv:'.$i];

		$pg .= "<td class=dr>$rej%</td>";

		if ($blockacc <= 0)
			$blkpct = '&nbsp;';
		else
			$blkpct = number_format(100.0 * $ans['w_diffacc:'.$i] / $blockacc, 3) . '%';

		$pg .= "<td class=dr>$blkpct</td>";

		if ($ans['w_elapsed:'.$i] > 3600)
			$uhr = $ans['w_hashrate1hr:'.$i];
		else
			$uhr = $ans['w_hashrate5m:'.$i];
		if ($uhr == '?')
			$uhr = '?GHs';
		else
		{
			$totrate += $uhr;
			$uhr = dsprate($uhr);
		}
		$pg .= "<td class=dr>$uhr</td>";

		$pg .= "</tr>\n";

		$offset++;
	}
 }
 return $pg;
}
#
function worktotal($offset, $totshare, $totdiff, $totinvalid, $totrate, $blockacc, $blockreward)
{
 $pg = '';
 $totrate = dsprate($totrate);
 if (($offset % 2) == 0)
	$row = 'even';
 else
	$row = 'odd';
 $pg .= "<tr class=$row><td class=dl>Total:</td><td colspan=2 class=dl></td>";
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
 $pg .= "<td class=dr>$totrate</td></tr>\n";
 return $pg;
}
#
function doworker($data, $user)
{
 $pg = '<h1>Workers</h1>';

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";

 $totshare = 0;
 $totdiff = 0;
 $totinvalid = 0;
 $totrate = 0;
 $offset = 0;
 $blockacc = 0;
 $blockreward = 0;

 $pg .= worktitle($data, $user);
 $pg .= workuser($data, $user, $offset, $totshare, $totdiff, $totinvalid,
			$totrate, $blockacc, $blockreward, false);
 $pg .= worktotal($offset, $totshare, $totdiff, $totinvalid, $totrate,
			$blockacc, $blockreward);

 if ($blockacc > 0 && $blockreward > 0)
 {
	$btc = btcfmt($totdiff / $blockacc * $blockreward);
	$pg .= '<tr><td colspan=8 class=dc>';
	$pg .= "<br>Payout est if block found at 100%: ~$btc BTC";
	$pg .= '</td></tr>';
 }

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
