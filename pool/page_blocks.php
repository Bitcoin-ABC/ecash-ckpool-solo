<?php
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

		$pg = "<h1>Last$num Block$s</h1>";
	}
	else
		$pg = '<h1>Blocks</h1>';

	$pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
	$pg .= "<tr class=title>";
	$pg .= "<td class=dr>#</td>";
	$pg .= "<td class=dl>Height</td>";
	if ($user !== null)
		$pg .= "<td class=dl>Who</td>";
	$pg .= "<td class=dr>Reward</td>";
	$pg .= "<td class=dc>When</td>";
	$pg .= "<td class=dr>Status</td>";
	$pg .= "<td class=dr>Diff</td>";
	$pg .= "<td class=dr>Diff%</td>";
	$pg .= "<td class=dr>CDF</td>";
	$pg .= "</tr>\n";
 }
 $blktot = 0;
 $nettot = 0;
 $i = 0;
 $orph = false;
 $csv = "Sequence,Height,Status,Timestamp,DiffAcc,NetDiff,Hash\n";
 if ($ans['STATUS'] == 'ok')
 {
	$tot = $ans['tot'];
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
		$stat = $ans['status:'.$i];
		if ($stat == 'Orphan')
		{
			$ex = 's';
			$orph = true;
			$seq = '';
		}
		else
			$seq = $tot--;
		if ($stat == '1-Confirm')
		{
			if (isset($data['info']['lastheight']))
			{
				$conf = 1 + $data['info']['lastheight'] - $hi;
				$stat = '+'.$conf.' Confirms';
			}
			else
				$stat = 'Conf';
		}

		$stara = '';
		$starp = '';
		if (isset($ans['status:'.($i+1)]))
			if ($ans['status:'.($i+1)] == 'Orphan'
			&&  $stat != 'Orphan')
			{
				$stara = '<span class=st1>*</span>';
				$starp = '<span class=st0>*</span>';
			}

		$diffacc = $ans['diffacc:'.$i];
		$acc = number_format($diffacc, 0);

		$netdiff = $ans['netdiff:'.$i];
		if ($netdiff > 0)
		{
			$pct = 100.0 * $diffacc / $netdiff;
			list($fg, $bg) = pctcolour($pct);
			$bpct = "<font color=$fg>$starp".number_format($pct, 2).'%</font>';
			$bg = " bgcolor=$bg";
			$blktot += $diffacc;
			if ($stat != 'Orphan')
				$nettot += $netdiff;

			$cdfv = 1 - exp(-1 * $diffacc / $netdiff);
			$cdf = number_format($cdfv, 2);
		}
		else
		{
			$bg = '';
			$bpct = '?';
			$cdf = '?';
		}

		if ($wantcsv === false)
		{
		 $pg .= "<tr class=$row>";
		 $pg .= "<td class=dr$ex>$seq</td>";
		 $pg .= "<td class=dl$ex>$hifld</td>";
		 if ($user !== null)
			$pg .= "<td class=dl$ex>".htmlspecialchars($ans['workername:'.$i]).'</td>';
		 $pg .= "<td class=dr$ex>".btcfmt($ans['reward:'.$i]).'</td>';
		 $pg .= "<td class=dl$ex>".gmdate('Y-m-d H:i:s+00', $ans['firstcreatedate:'.$i]).'</td>';
		 $pg .= "<td class=dr$ex>".$stat.'</td>';
		 $pg .= "<td class=dr>$stara$acc</td>";
		 $pg .= "<td class=dr$bg>$bpct</td>";
		 $pg .= "<td class=dr>$cdf</td>";
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
 if ($nettot > 0)
 {
	if (($i % 2) == 0)
		$row = 'even';
	else
		$row = 'odd';

	$pct = 100.0 * $blktot / $nettot;
	list($fg, $bg) = pctcolour($pct);
	$bpct = "<font color=$fg>".number_format($pct, 2).'%</font>';
	$bg = " bgcolor=$bg";

	$pg .= "<tr class=$row>";
	$pg .= '<td colspan=2 class=dr>Total:</td>';
	$pg .= '<td class=dl colspan=';
	if ($user === null)
		$pg .= '4';
	else
		$pg .= '5';
	$pg .= '></td>';
	$pg .= "<td class=dr$bg>".$bpct.'</td>';
	$pg .= "<td></td></tr>\n";
	if ($orph === true)
	{
		$pg .= '<tr><td colspan=';
		if ($user === null)
			$pg .= '7';
		else
			$pg .= '8';
		$pg .= ' class=dc><font size=-1><span class=st1>*</span>';
		$pg .= '% total is adjusted to include orphans correctly';
		$pg .= '</font></td></tr>';
	}
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
