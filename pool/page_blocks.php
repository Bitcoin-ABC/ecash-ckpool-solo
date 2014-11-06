<?php
#
function pctcolour($pct)
{
 if ($pct == 100)
 {
	$fg = '#fff';
	$bg = '#000';
 }

 if ($pct < 100)
 {
	$grn = (2.0 - log10($pct)) * 255;
	if ($grn < 0)
		$grn = 0;
	if ($grn > 255)
		$grn = 255;

	if ($grn > 190)
		$fg = '#00f';
	else
		$fg = '#fff';
	$bg = sprintf("#00%02x00", $grn);
 }

 if ($pct > 100)
 {
	$red = (log10(pow($pct,4.0)) - 8.0) / 3.0 * 255;
	if ($red < 0)
		$red = 0;
	if ($red > 255)
		$red = 255;

	$fg = '#fff';
	$bg = sprintf("#%02x0000", $red);
 }

 return array($fg, $bg);
}
#
function doblocks($data, $user)
{
 $blink = '<a href=https://blockchain.info/block-height/';

 $pg = '<h1>Blocks</h1>';

 $ans = getBlocks($user);

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dl>Height</td>";
 $pg .= "<td class=dl>Who</td>";
 $pg .= "<td class=dr>Reward</td>";
 $pg .= "<td class=dc>When</td>";
 $pg .= "<td class=dr>Status</td>";
 $pg .= "<td class=dr>Diff</td>";
 $pg .= "<td class=dr>%</td>";
 $pg .= "</tr>\n";
 $blktot = 0;
 $nettot = 0;
 $i = 0;
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
		$stat = $ans['status:'.$i];
		if ($stat == 'Orphan')
			$ex = 's';
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
		}
		else
		{
			$bg = '';
			$bpct = '?';
		}

		$pg .= "<tr class=$row>";
		$pg .= "<td class=dl$ex>$hifld</td>";
		$pg .= "<td class=dl$ex>".htmlspecialchars($ans['workername:'.$i]).'</td>';
		$pg .= "<td class=dr$ex>".btcfmt($ans['reward:'.$i]).'</td>';
		$pg .= "<td class=dl$ex>".gmdate('Y-m-d H:i:s+00', $ans['firstcreatedate:'.$i]).'</td>';
		$pg .= "<td class=dr$ex>".$stat.'</td>';
		$pg .= "<td class=dr>$stara$acc</td>";
		$pg .= "<td class=dr$bg>$bpct</td>";
		$pg .= "</tr>\n";
	}
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
	$pg .= "<td class=dl colspan=6></td>";
	$pg .= "<td class=dr$bg>".$bpct.'</td>';
	$pg .= "</tr>\n";
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_blocks($page, $menu, $name, $user)
{
 gopage(NULL, 'doblocks', $page, $menu, $name, $user);
}
#
?>
