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
function doblocks($data, $user)
{
 $blink = '<a href=https://blockchain.info/block-height/';

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
	if ($ans['STATUS'] == 'ok' and isset($ans['s_rows']) and $ans['s_rows'] > 0)
	{
		$pg .= '<h1>Block Statistics</h1>';
		$pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
		$pg .= "<tr class=title>";
		$pg .= "<td class=dl>Description</td>";
		$pg .= "<td class=dr>Time</td>";
		$pg .= "<td class=dr>MeanTx%</td>";
		$pg .= "<td class=dr>Diff%</td>";
		$pg .= "<td class=dr>Mean%</td>";
		$pg .= "<td class=dr>CDF[Erl]</td>";
		$pg .= "<td class=dr>Luck%</td>";
		$pg .= "</tr>\n";

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

			$pg .= "<tr class=$row>";
			$pg .= "<td class=dl>$desc Blocks</td>";
			$pg .= "<td class=dr>$age</td>";
			$pg .= "<td class=dr>$txm%</td>";
			$pg .= "<td class=dr>$diff%</td>";
			$pg .= "<td class=dr>$mean%</td>";
			$pg .= "<td class=dr$bg>$cdferldsp</td>";
			$pg .= "<td class=dr>$luck%</td>";
			$pg .= "</tr>\n";
		}
		$pg .= "</table>\n";
	}

	if ($ans['STATUS'] == 'ok')
	{
		$count = $ans['rows'];
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
		$pg .= '<h1>Blocks</h1>';

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

	$pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
	$pg .= "<tr class=title>";
	$pg .= "<td class=dr>#</td>";
	$pg .= "<td class=dl>Height</td>";
	if ($user !== null)
		$pg .= "<td class=dl>Who</td>";
	$pg .= "<td class=dr>Block Reward</td>";
	$pg .= "<td class=dc>When</td>";
	$pg .= "<td class=dr>Status</td>";
	$pg .= "<td class=dr>Diff</td>";
	$pg .= "<td class=dr>Diff%</td>";
	$pg .= "<td class=dr>CDF</td>";
	$pg .= "<td class=dr>B</td>";
	$pg .= "</tr>\n";
 }
 $blktot = 0;
 $nettot = 0;
 $i = 0;
 $cnt = 0;
 $orph = false;
 $csv = "Sequence,Height,Status,Timestamp,DiffAcc,NetDiff,Hash\n";
 if ($ans['STATUS'] == 'ok')
 {
	$count = $ans['rows'];
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

		if ($diffratio > 0)
		{
			$pct = 100.0 * $diffratio;
			list($fg, $bg) = pctcolour($pct);
			$bpct = "<font color=$fg>$approx".number_format($pct, 3).'%</font>';
			$bg = " bgcolor=$bg";
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
		}

		if ($wantcsv === false)
		{
		 $pg .= "<tr class=$row>";
		 $pg .= "<td class=dr$ex>$seq</td>";
		 $pg .= "<td class=dl$ex>$hifld</td>";
		 if ($user !== null)
			$pg .= "<td class=dl$ex>".htmlspecialchars($ans['workername:'.$i]).'</td>';
		 $pg .= "<td class=dr$ex>".btcfmt($ans['reward:'.$i]).'</td>';
		 $pg .= "<td class=dl$ex>".utcd($ans['firstcreatedate:'.$i]).'</td>';
		 $pg .= "<td class=dr$ex>$tt$stat</td>";
		 $pg .= "<td class=dr>$stara$approx$acc</td>";
		 $pg .= "<td class=dr$bg>$bpct</td>";
		 $pg .= "<td class=dr>$cdfdsp</td>";
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
 }
 if ($wantcsv === true)
 {
	echo $csv;
	exit(0);
 }
 if ($orph === true)
 {
	$pg .= '<tr><td colspan=';
	if ($user === null)
		$pg .= '7';
	else
		$pg .= '8';
	$pg .= ' class=dc><font size=-1><span class=st1>*</span>';
	$pg .= 'Orphans/Rejects count as shares but not as a block in calculations';
	$pg .= '</font></td></tr>';
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
