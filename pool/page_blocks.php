<?php
#
function erlcolour($erl)
{
 if ($erl <= 0.5)
 {
	$grn = (-0.3 - log10($erl)) * 383;
	if ($grn < 0)
		$grn = 0;
	if ($grn > 255)
		$grn = 255;

	if ($grn > 190)
		$fg = 'blue';
	else
		$fg = 'white';
	$bg = sprintf("#00%02x00", $grn);
 }
 else # ($erl > 0.5)
 {
	$red = (-0.3 - log10(1.0 - $erl)) * 255;
	if ($red < 0)
		$red = 0;
	if ($red > 255)
		$red = 255;

	$fg = 'white';
	$bg = sprintf("#%02x0000", $red);
 }

 return array($fg, $bg);
}
#
function pctcolour($pct)
{
 if ($pct == 100)
 {
	$fg = 'white';
	$bg = 'black';
 }

 if ($pct < 100)
 {
	$grn = (2.0 - log10($pct)) * 255;
	if ($grn < 0)
		$grn = 0;
	if ($grn > 255)
		$grn = 255;

	if ($grn > 190)
		$fg = 'blue';
	else
		$fg = 'white';
	$bg = sprintf("#00%02x00", $grn);
 }

 if ($pct > 100)
 {
	$red = (log10(pow($pct,4.0)) - 8.0) / 3.0 * 255;
	if ($red < 0)
		$red = 0;
	if ($red > 255)
		$red = 255;

	$fg = 'white';
	$bg = sprintf("#%02x0000", $red);
 }

 return array($fg, $bg);
}
#
function mthcolour($luck)
{
 if ($luck == 1.0)
 {
	$fg = 'white';
	$bg = 'black';
 }
 else if ($luck > 1.0)
 {
	// 1.0 .. 1.1 (> 1.1 = max)
	$grn = ($luck - 1.0) * 2550.0;
	if ($grn > 255)
		$grn = 255;
	if ($grn < 0)
		$grn = 0;
	if ($grn > 190)
		$fg = 'blue';
	else
		$fg = 'white';
	$bg = sprintf("#00%02x00", $grn);
 }
 else
 {
	// 0.9 .. 1.0 (< 0.9 = max)
	$red = (1.0 - $luck) * 2550.0;
	if ($red > 255)
		$red = 255;
	if ($red < 0)
		$red = 0;
	$fg = 'white';
	$bg = sprintf("#%02x0000", $red);
 }
 return array($fg, $bg);
}
#
function statstable($poolfee, $ans, $data)
{
	if ($ans['STATUS'] != 'ok' or !isset($ans['s_rows']) or $ans['s_rows'] < 1)
		return '';

	$pg = '<h1>Block Statistics</h1>';
	$pg .= "<table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= "<thead><tr class=title>";
	$pg .= "<td class=dl>Description</td>";
	$pg .= "<td class=dr>Time</td>";
	$pg .= "<td class=dr>MeanTx%</td>";
	$pg .= "<td class=dr>Diff%</td>";
	$pg .= "<td class=dr>Mean%</td>";
	$pg .= "<td class=dr>CDF[Erl]</td>";
	$pg .= "<td class=dr>Luck%</td>";

	$tt = "<span class=q onclick='tip(\"ppst\",6000)'>";
	$tt .= '?</span><span class=tip0>';
	$tt .= "<span class=notip id=ppst>";
	$tt .= "Pool PPS%: MeanTx% * Luck% minus the pool fee</span></span>";

	$pg .= "<td class=dr>${tt}PPS%</td>";
	$pg .= "</tr></thead><tbody>\n";

	$since = $data['info']['lastblock'];

	$count = $ans['s_rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$desc = $ans['s_desc:'.$i];
		$age = daysago($since - $ans['s_prevcreatedate:'.$i]);
		$diff = number_format(100 * $ans['s_diffratio:'.$i], 2);
		$mean = number_format(100 * $ans['s_diffmean:'.$i], 2);

		$cdferl = $ans['s_cdferl:'.$i];
		list($fg, $bg) = erlcolour($cdferl);
		$cdferldsp = "<font color=$fg>".number_format($cdferl, 4).'</font>';
		$bg = " bgcolor=$bg";

		$luck = number_format(100 * $ans['s_luck:'.$i], 2);
		$txm = number_format(100 * $ans['s_txmean:'.$i], 1);

		$o = number_format((100 - $poolfee) * $ans['s_txmean:'.$i] / $ans['s_diffmean:'.$i], 2);

		$pg .= "<tr class=$row>";
		$pg .= "<td class=dl>$desc Blocks</td>";
		$pg .= "<td class=dr>$age</td>";
		$pg .= "<td class=dr>$txm%</td>";
		$pg .= "<td class=dr>$diff%</td>";
		$pg .= "<td class=dr>$mean%</td>";
		$pg .= "<td class=dr$bg>$cdferldsp</td>";
		$pg .= "<td class=dr>$luck%</td>";
		$pg .= "<td class=dr>$o%</td>";
		$pg .= "</tr>\n";
	}
	$pg .= "</tbody></table>\n";
	return $pg;
}
#
function monthtable($poolfee, $ans, $limit)
{
	if ($ans['STATUS'] != 'ok' or !isset($ans['rows']) or $ans['rows'] < 1)
		return '';

	$nowmon = intval(gmdate('n', $ans['STAMP']));
	$nowyyyy = intval(gmdate('Y', $ans['STAMP']));

	$pg = '<h1>Monthly Statistics</h1>';
	$pg .= "<table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= "<thead><tr class=title>";
	$pg .= "<td class=dl>UTC Month</td>";
	$pg .= "<td class=dr>Pool Avg</td>";
	$pg .= "<td class=dr>Blocks</td>";
	$pg .= "<td class=dr>Expected</td>";
	$pg .= "<td class=dr>Mean Diff%</td>";
	$pg .= "<td class=dr>MeanTx%</td>";
	$pg .= "<td class=dr>Luck%</td>";
	$pg .= "<td class=dr>PPS%</td>";
	$pg .= "</tr></thead>\n";

	$pg .= '<tbody>';
	$count = $ans['rows'];
	$rout = $bcount = $bcd = $bmon = $byyyy = $bdiffacc = $bdiffratio = $btxn = 0;
	$skipped = false;
	for ($i = 0; $i < $count; $i++)
	{
		$conf = $ans['confirmed:'.$i];
		// Skip leading orphans
		if (!$skipped && ($conf == 'O' || $conf == 'R'))
			continue;

		$skipped = true;

		// If anything is missing, skip this table
		$diffratio = $ans['diffratio:'.$i];
		if ($diffratio == '?')
			break;

		$cd = $ans['firstcreatedate:'.$i];
		$mon = intval(gmdate('n', $cd));
		$yyyy = intval(gmdate('Y', $cd));
		// all orphans after a block must be included with that block
		if (($conf != 'O' && $conf != 'R')
		&&  ($mon != $bmon || $yyyy != $byyyy))
		{
			if ($bcount != 0)
			{
				if (($rout % 2) == 0)
					$row = 'even';
				else
					$row = 'odd';

				if ($bmon == $nowmon && $byyyy == $nowyyyy)
					$dots = '&hellip;';
				else
					$dots = '';

				$elap = $bcd - $cd;
				$phr = ($bdiffacc / $elap) * pow(2, 32);
				$phrdsp = siprefmt($phr);

				$name = gmdate('Y M', $bcd);
				$exc = number_format($bdiffratio, 2);
				if ($bdiffratio > $bcount)
					$bcol = 'darkred';
				else
					$bcol = 'darkgreen';
				$md = number_format(100 * $bdiffratio / $bcount, 2);
				$mr = number_format(100 * $btxn / $bcount, 2);
				$ml = $bcount / $bdiffratio;
				$mldsp = number_format(100 * $ml, 2);
				$oa = (100 - $poolfee) * ($bcount / $bdiffratio) * ($btxn / $bcount);
				$odsp = number_format($oa, 2);
				list($fg, $bg) = mthcolour($ml);

				$pg .= "<tr class=$row>";
				$pg .= "<td class=dl>$name$dots</td>";
				$pg .= "<td class=dr>${phrdsp}Hs</td>";
				$pg .= "<td class=dr bgcolor=$bg><font color=$fg>$bcount</font></td>";
				$pg .= "<td class=dr>$exc</td>";
				$pg .= "<td class=dr>$md%</td>";
				$pg .= "<td class=dr>$mr%</td>";
				$pg .= "<td class=dr>$mldsp%</td>";
				$pg .= "<td class=dr>$odsp%</td>";
				$pg .= "</tr>\n";

				$rout++;
			}
			if ($rout > $limit)
				break;

			$bcd = $cd;
			$bmon = $mon;
			$byyyy = $yyyy;
			$bcount = $bdiffacc = $bdiffratio = $btxn = 0;
		}
		$bdiffratio += floatval($ans['diffratio:'.$i]);
		$bdiffacc += floatval($ans['diffacc:'.$i]);

		if ($conf != 'O' and $conf != 'R')
		{
			$height = $ans['height:'.$i];
			$reward = floatval($ans['reward:'.$i]);
			$re = 5000000000.0 * pow(0.5, floor($height / 210000.0));
			$btxn += $reward / $re;
			$bcount++;
		}
	}
	$pg .= '</tbody></table>';

	return $pg;
}
#
function doblocks($data, $user)
{
 $blink = '<a href=https://www.blocktrail.com/BTC/block/';
 $poolfee = 0.9; # pool fee as a % out of 100

 $pg = '';

 if ($user === null)
	$ans = getBlocks('Anon');
 else
	$ans = getBlocks($user);

 if (nuem(getparam('csv', true)))
	$wantcsv = false;
 else
	$wantcsv = true;

 if ($wantcsv === false)
 {
	$pg .= statstable($poolfee, $ans, $data);

	$pg .= monthtable($poolfee, $ans, 7);

	if ($ans['STATUS'] == 'ok')
	{
		$count = $ans['rows'];
		$histsiz = $ans['historysize'] . ' ';
		if ($count == 1)
		{
			$num = '';
			$s = '';
		}
		else
		{
			$num = " $count";
			$s = 's';
		}

		$pg .= "<h1>Last$num Block$s</h1>";
	}
	else
	{
		$histsiz = '';
		$pg .= '<h1>Blocks</h1>';
	}

	list($fg, $bg) = pctcolour(25.0);
	$pg .= "<span style='background:$bg; color:$fg;'>";
	$pg .= "&nbsp;Green&nbsp;</span>&nbsp;";
	$pg .= 'is good luck. Lower Diff% and brighter green is better luck.<br>';
	list($fg, $bg) = pctcolour(100.0);
	$pg .= "<span style='background:$bg; color:$fg;'>";
	$pg .= "&nbsp;100%&nbsp;</span>&nbsp;";
	$pg .= 'is expected average.&nbsp;';
	list($fg, $bg) = pctcolour(400.0);
	$pg .= "<span style='background:$bg; color:$fg;'>";
	$pg .= "&nbsp;Red&nbsp;</span>&nbsp;";
	$pg .= 'is bad luck. Higher Diff% and brighter red is worse luck.<br><br>';

	$pg .= "<table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= "<thead><tr class=title>";
	$pg .= "<td class=dr>#</td>";
	$pg .= "<td class=dl>Height</td>";
	if ($user !== null)
		$pg .= "<td class=dl>Who</td>";
	$pg .= "<td class=dr>Block Reward</td>";
	$pg .= "<td class=dc>When UTC</td>";
	$pg .= "<td class=dl>Status</td>";
	$pg .= "<td class=dr>Diff</td>";
	$pg .= "<td class=dr>Diff%</td>";
	$pg .= "<td class=dr>CDF</td>";
	$pg .= "<td class=dr>${histsiz}Luck%</td>";
	$pg .= "<td class=dr>B</td>";
	$pg .= "</tr></thead>\n";
 }
 $blktot = 0;
 $nettot = 0;
 $i = 0;
 $cnt = 0;
 $orph = false;
 $csv = "Sequence,Height,Status,Timestamp,DiffAcc,NetDiff,Hash\n";
 if ($ans['STATUS'] == 'ok')
 {
	$pg .= '<tbody>';
	$count = $ans['rows'];
	$colpct = 0;
	for ($i = $count - 1; $i >= 0; $i--)
	{
		$conf = $ans['confirmed:'.$i];
		$diffratio = $ans['diffratio:'.$i];
		if ($diffratio > 0)
		{
			$colpct += 100.0 * $diffratio;
			$ans['colpct:'.$i] = $colpct;
			if ($conf != 'O' and $conf != 'R')
				$colpct = 0;
		}
	}
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$hi = $ans['height:'.$i];
		$hifld = "$blink$hi>$hi</a>";

		$ex = '';
		$conf = $ans['confirmed:'.$i];
		$stat = $ans['status:'.$i];
		$inf = $ans['info:'.$i];
		$tt = '';
		if ($conf == 'O' or $conf == 'R')
		{
			$ex = 's';
			$orph = true;
			$seq = '';
			$nn = $cnt;
			if ($conf == 'R')
			{
				addTips();
				$in = explode(':', $inf, 2);
				if (trim($in[0]) != '')
					$stat = trim($in[0]);
				if (count($in) < 2 or trim($in[1]) == '')
				{
					$tip = 'Share diff was VERY close<br>';
					$tip .= 'so we tested it,<br>';
					$tip .= "but it wasn't worthy<br>";
				}
				else
					$tip = str_replace('+', '<br>', trim($in[1]));

				$tt = "<span class=q onclick='tip(\"btip$i\",6000)'>";
				$tt .= '?</span><span class=tip0>';
				$tt .= "<span class=notip id=btip$i>";
				$tt .= "$tip</span></span>";
			}
		}
		else
		{
			$seq = $ans['seq:'.$i];
			$nn = ++$cnt;
		}
		if ($conf == '1')
		{
			if (isset($data['info']['lastheight']))
			{
				$confn = 1 + $data['info']['lastheight'] - $hi;
				$stat = '+'.$confn.' Confirms';
			}
			else
				$stat = 'Conf';
		}

		$stara = '';
		if ($conf == 'O' or $conf == 'R')
			$stara = '<span class=st1>*</span>';

		if (isset($ans['statsconf:'.$i]))
		{
			if ($ans['statsconf:'.$i] == 'Y')
				$approx = '';
			else
				$approx = '~';
		}
		else
			$approx = '';

		$diffacc = $ans['diffacc:'.$i];
		$acc = number_format($diffacc, 0);

		$netdiff = $ans['netdiff:'.$i];
		$diffratio = $ans['diffratio:'.$i];
		$cdf = $ans['cdf:'.$i];
		$luck = $ans['luck:'.$i];
		$hist = $ans['luckhistory:'.$i];

		if ($diffratio > 0)
		{
			$pct = 100.0 * $diffratio;
			$colpct = $ans['colpct:'.$i];
			if ($conf != 'O' and $conf != 'R')
			{
				list($fg, $bg) = pctcolour($colpct);
				$bpct = "<font color=$fg>$approx".number_format($pct, 3).'%</font>';
				$bg = " bgcolor=$bg";
				$histdsp = "$approx".number_format(100.0 * $hist, 2).'%';
			}
			else
			{
				$bpct = "$approx".number_format($pct, 3).'%';
				$bg = '';
				$histdsp = '&nbsp;';
			}
			$blktot += $diffacc;
			if ($conf != 'O' and $conf != 'R')
				$nettot += $netdiff;

			$cdfdsp = number_format($cdf, 3);
		}
		else
		{
			$bg = '';
			$bpct = '?';
			$cdfdsp = '?';
			$histdsp = '?';
		}

		if ($wantcsv === false)
		{
		 $pg .= "<tr class=$row>";
		 $pg .= "<td class=dr$ex>$seq</td>";
		 $pg .= "<td class=dl$ex>$hifld</td>";
		 if ($user !== null)
		 {
			list($abr, $nam) = dspname($ans['workername:'.$i]);
			$pg .= "<td class=dl$ex>$nam</td>";
		 }
		 $pg .= "<td class=dr$ex>".btcfmt($ans['reward:'.$i]).'</td>';
		 $pg .= "<td class=dc$ex>".utcd($ans['firstcreatedate:'.$i], false, false).'</td>';
		 $pg .= "<td class=dl$ex>$tt$stat</td>";
		 $pg .= "<td class=dr>$stara$approx$acc</td>";
		 $pg .= "<td class=dr$bg>$bpct</td>";
		 $pg .= "<td class=dr>$cdfdsp</td>";
		 $pg .= "<td class=dr>$histdsp</td>";
		 $pg .= "<td class=dr>$nn</td>";
		 $pg .= "</tr>\n";
		}
		else
		{
		 $csv .= "$seq,";
		 $csv .= "$hi,";
		 $csv .= "\"$stat\",";
		 $csv .= $ans['firstcreatedate:'.$i].',';
		 $csv .= "$diffacc,";
		 $csv .= "$netdiff,";
		 $csv .= $ans['blockhash:'.$i]."\n";
		}
	}
	$pg .= '</tbody>';
 }
 if ($wantcsv === true)
 {
	echo $csv;
	exit(0);
 }
 if ($orph === true)
 {
	$pg .= '<tfoot><tr><td colspan=';
	if ($user === null)
		$pg .= '8';
	else
		$pg .= '9';
	$pg .= ' class=dc><font size=-1><span class=st1>*</span>';
	$pg .= 'Orphans/Rejects count as shares but not as a block in calculations';
	$pg .= '</font></td></tr></tfoot>';
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_blocks($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doblocks', $page, $menu, $name, $user);
}
#
?>
