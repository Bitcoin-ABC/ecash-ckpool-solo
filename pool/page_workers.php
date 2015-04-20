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
function workhashorder($a, $b)
{
 return $b['w_uhr'] - $a['w_uhr'];
}
#
function workuser($data, $user, &$offset, &$totshare, &$totdiff,
			&$totinvalid, &$totrate, &$blockacc,
			&$blockreward, $old = false, $srt = false,
			 $one = false, &$title)
{
 $ans = getWorkers($user);

 $pg = '';
 if ($ans['STATUS'] == 'ok')
 {
	if (isset($ans['blockacc']))
		$blockacc = $ans['blockacc'];
	if (isset($ans['blockreward']))
		$blockreward = $ans['blockreward'];
	if ($one === true && isset($ans['oldworkers']))
	{
		$days = intval($ans['oldworkers']);
		if ($days != 0)
			$title = '&nbsp;(active during the last '.$days.' day'.
				 (($days==1)?'':'s').')';
	}
	$all = array();
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		$lst = $ans['STAMP'] - $ans['w_lastshare:'.$i];
		if ($old !== false && $lst > $old)
			continue;

		if ($ans['w_elapsed:'.$i] > 3600)
			$uhr = $ans['w_hashrate1hr:'.$i];
		else
			$uhr = $ans['w_hashrate5m:'.$i];

		$all[] = array('workername' => $ans['workername:'.$i],
				'w_lastshare' => $ans['w_lastshare:'.$i],
				'w_lastdiff' => $ans['w_lastdiff:'.$i],
				'w_shareacc' => $ans['w_shareacc:'.$i],
				'w_diffacc' => $ans['w_diffacc:'.$i],
				'w_diffinv' => $ans['w_diffinv:'.$i],
				'w_lastdiff' => $ans['w_lastdiff:'.$i],
				'w_uhr' => $uhr);
	}

	if ($srt)
		usort($all, 'workhashorder');

	for ($i = 0; $i < $count; $i++)
	{
		$lst = $ans['STAMP'] - $all[$i]['w_lastshare'];
		if ($old !== false && $lst > $old)
			continue;

		if ((($offset) % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.htmlspecialchars($all[$i]['workername']).'</td>';
		if ($all[$i]['w_lastdiff'] > 0)
			$ld = difffmt($all[$i]['w_lastdiff']);
		else
			$ld = '&nbsp;';
		$pg .= "<td class=dr>$ld</td>";

		$pg .= '<td class=dr>'.howlongago($lst).'</td>';

		$shareacc = number_format($all[$i]['w_shareacc'], 0);
		$totshare += $all[$i]['w_shareacc'];
		$diffacc = number_format($all[$i]['w_diffacc'], 0);
		$totdiff += $all[$i]['w_diffacc'];
		$pg .= "<td class=dr>$shareacc</td>";
		$pg .= "<td class=dr>$diffacc</td>";

		$dtot = $all[$i]['w_diffacc'] + $all[$i]['w_diffinv'];
		if ($dtot > 0)
			$rej = number_format(100.0 * $all[$i]['w_diffinv'] / $dtot, 3);
		else
			$rej = '0';
		$totinvalid +=  $all[$i]['w_diffinv'];

		$pg .= "<td class=dr>$rej%</td>";

		if ($blockacc <= 0)
			$blkpct = '&nbsp;';
		else
			$blkpct = number_format(100.0 * $all[$i]['w_diffacc'] / $blockacc, 3) . '%';

		$pg .= "<td class=dr>$blkpct</td>";

		$uhr = $all[$i]['w_uhr'];
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
 $title = '';

 $pg = "<table callpadding=0 cellspacing=0 border=0>\n";

 $totshare = 0;
 $totdiff = 0;
 $totinvalid = 0;
 $totrate = 0;
 $offset = 0;
 $blockacc = 0;
 $blockreward = 0;

 $pg .= worktitle($data, $user);
 $pg .= workuser($data, $user, $offset, $totshare, $totdiff, $totinvalid,
			$totrate, $blockacc, $blockreward, false, true, true,
			$title);
 $pg .= worktotal($offset, $totshare, $totdiff, $totinvalid, $totrate,
			$blockacc, $blockreward);

 if (false && $blockacc > 0 && $blockreward > 0)
 {
	$btc = btcfmt($totdiff / $blockacc * $blockreward);
	$pg .= '<tr><td colspan=8 class=dc>';
	$pg .= "<br>Payout est if block found at 100%: ~$btc BTC";
	$pg .= '</td></tr>';
 }

 $pg .= "</table>\n";

 return "<h1>Workers$title</h1>".$pg;
}
#
function doworkers($data, $user)
{
 $pg = doworker($data, $user);
 return $pg;
}
#
function show_workers($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doworkers', $page, $menu, $name, $user);
}
#
?>
