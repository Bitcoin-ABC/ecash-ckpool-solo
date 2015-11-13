<?php
#
function worktitle($data, $user)
{
 addSort();
 $r = "input type=radio name=srt onclick=\"sott('worksrt',this);\"";
 $pg  = '<tr class=title>';
 $pg .= "<td class=dl>Worker <span class=nb>Name:<$r id=srtwrk data-sf=s0></span></td>";
 $pg .= '<td class=dr>Work Diff</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtlst data-sf=n2>:Last</span> Share</td>";
 $pg .= '<td class=dr>Shares</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtdiff data-sf=r4>:Diff</span></td>";
 $pg .= "<td class=dr><span class=nb><$r id=srtshrate data-sf=r5>:Share Rate</span></td>";
 $pg .= '<td class=dr>&laquo;Elapsed</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtinv data-sf=r7>:Invalid</span></td>";
 $pg .= '<td class=dr>Block %</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtrate data-sf=r9>:Hash</span> Rate</td>";
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
			&$totshrate, &$totinvalid, &$totrate, &$blockacc,
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
	$now = $ans['STAMP'];
	for ($i = 0; $i < $count; $i++)
	{
		$lst = $now - $ans['w_lastshare:'.$i];
		if ($old !== false && $lst > $old)
			continue;

		if ($ans['w_elapsed:'.$i] > 3600)
			$uhr = $ans['w_hashrate1hr:'.$i];
		else
			$uhr = $ans['w_hashrate5m:'.$i];

		$all[] = array('workername' => $ans['workername:'.$i],
				'w_lastshare' => $ans['w_lastshare:'.$i],
				'w_lastshareacc' => $ans['w_lastshareacc:'.$i],
				'w_lastdiff' => $ans['w_lastdiff:'.$i],
				'w_shareacc' => $ans['w_shareacc:'.$i],
				'w_diffacc' => $ans['w_diffacc:'.$i],
				'w_diffinv' => $ans['w_diffinv:'.$i],
				'w_lastdiff' => $ans['w_lastdiff:'.$i],
				'w_active_diffacc' => $ans['w_active_diffacc:'.$i],
				'w_active_start' => $ans['w_active_start:'.$i],
				'w_uhr' => $uhr);
	}

	if ($srt)
		usort($all, 'workhashorder');

	for ($i = 0; $i < $count; $i++)
	{
		$lst = $now - $all[$i]['w_lastshare'];
		if ($old !== false && $lst > $old)
			continue;

		$lstacc = $now - $all[$i]['w_lastshareacc'];

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

		$pg .= "<td class=dr data-srt=$lstacc>".howlongago($lstacc).'</td>';

		$shareacc = number_format($all[$i]['w_shareacc'], 0);
		$totshare += $all[$i]['w_shareacc'];
		$dacc = $all[$i]['w_diffacc'];
		$diffacc = number_format($dacc, 0);
		$ds = round($dacc);
		$totdiff += $dacc;
		$pg .= "<td class=dr>$shareacc</td>";
		$pg .= "<td class=dr data-srt=$ds>$diffacc</td>";

		$acthr = '0';
		$acthrv = 0;
		$actstt = $all[$i]['w_active_start'];
		if ($actstt <= 0 || ($now - $actstt) < 0)
			$actsin = '&nbsp;';
		else
		{
			$actsin = howmanyhrs($now - $actstt);
			$elapsed = $now - $actstt;
			if ($elapsed > 0)
			{
				$acthrv = $all[$i]['w_active_diffacc'] *
						pow(2,32) / $elapsed;
				$acthr = dsprate($acthrv);
				$totshrate += $acthrv;
			}
		}
		$pg .= "<td class=dr data-srt=$acthrv>$acthr</td>";
		$pg .= "<td class=dr>$actsin</td>";

		$dinv = $all[$i]['w_diffinv'];
		$dtot = $dacc + $dinv;
		if ($dtot > 0)
		{
			$rejf = $dinv / $dtot;
			$rej = number_format(100.0 * $rejf, 3);
		}
		else
		{
			$rejf = 0;
			$rej = '0';
		}
		$totinvalid += $dinv;

		$pg .= "<td class=dr data-srt=$rejf>$rej%</td>";

		if ($blockacc <= 0)
			$blkpct = '&nbsp;';
		else
			$blkpct = number_format(100.0 * $dacc / $blockacc, 3) . '%';

		$pg .= "<td class=dr>$blkpct</td>";

		$uhr = $all[$i]['w_uhr'];
		if ($uhr == '?')
		{
			$uhr = '?GHs';
			$su = 0;
		}
		else
		{
			$su = round($uhr);
			$totrate += $uhr;
			$uhr = dsprate($uhr);
		}
		$pg .= "<td class=dr data-srt=$su>$uhr</td>";

		$pg .= "</tr>\n";

		$offset++;
	}
 }
 return $pg;
}
#
function worktotal($offset, $totshare, $totdiff, $totshrate, $totinvalid,
			$totrate, $blockacc, $blockreward)
{
 $pg = '';
 $totshrate = dsprate($totshrate);
 $totrate = dsprate($totrate);
 if (($offset % 2) == 0)
	$row = 'even';
 else
	$row = 'odd';
 $pg .= "<tr class=$row><td class=dl>Total: $offset</td><td colspan=2 class=dl></td>";
 $shareacc = number_format($totshare, 0);
 $pg .= "<td class=dr>$shareacc</td>";
 $diffacc = number_format($totdiff, 0);
 $pg .= "<td class=dr>$diffacc</td>";
 $pg .= "<td class=dr>$totshrate</td><td>&nbsp;</td>";
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
 $totshrate = 0;
 $totinvalid = 0;
 $totrate = 0;
 $offset = 0;
 $blockacc = 0;
 $blockreward = 0;

 $pg .= worktitle($data, $user);
 $pg .= workuser($data, $user, $offset, $totshare, $totdiff, $totshrate,
			$totinvalid, $totrate, $blockacc, $blockreward,
			false, true, true, $title);
 $pg .= worktotal($offset, $totshare, $totdiff, $totshrate, $totinvalid,
			$totrate, $blockacc, $blockreward);

 if (false && $blockacc > 0 && $blockreward > 0)
 {
	$btc = btcfmt($totdiff / $blockacc * $blockreward);
	$pg .= '<tr><td colspan=8 class=dc>';
	$pg .= "<br>Payout est if block found at 100%: ~$btc BTC";
	$pg .= '</td></tr>';
 }

 $pg .= "</table>\n";
 $pg .= "<script type='text/javascript'>\n";
 $pg .= "sotc('worksrt','srtrate');</script>\n";

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
