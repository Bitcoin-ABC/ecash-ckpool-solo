<?php
#
function worktable()
{
 $pg = "<script type='text/javascript'>\n";
 $pg .= "function wkdet(n,i){var t=document.getElementById(n);if(i&&t){var b,cs,j,c,a;b=i.checked;cs=t.getElementsByTagName('td');for(j=0;c=cs[j];j++)
{a=c.getAttribute('data-hid');if(a){if(b){c.className=a}else{c.className='hid'}}}}}";
 $pg .= "</script>\n";
 $pg .= "Show Details for Invalids: <input type=checkbox onclick='wkdet(\"wkt\",this)'><br>";
 $pg .= "<table id=wkt cellpadding=0 cellspacing=0 border=0>\n";
 return $pg;
}
#
function worktitle($data, $user)
{
 addSort();
 $r = "input type=radio name=srt onclick=\"sott('worksrt',this);\"";
 $pg  = '<thead><tr class=title>';
 $pg .= "<td class=dl>Worker <span class=nb>Name:<$r id=srtwrk data-sf=s0></span></td>";
 $pg .= '<td class=dr>Work Diff</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtlst data-sf=n2>:Last</span> Share</td>";
 $pg .= '<td class=dr>Shares</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtdiff data-sf=r4>:Diff</span></td>";
 $pg .= "<td class=dr><span class=nb><$r id=srtshrate data-sf=r5>:Share Rate</span></td>";
 $pg .= '<td class=dr>&laquo;Elapsed</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtinv data-sf=r7>:Invalid</span></td>";
 $pg .= "<td class=hid data-hid=dr><span class=nb><$r id=srtstale data-sf=r8>:Stale</span></td>";
 $pg .= "<td class=hid data-hid=dr><span class=nb><$r id=srtdup data-sf=r9>:Dup</span></td>";
 $pg .= "<td class=hid data-hid=dr><span class=nb><$r id=srthi data-sf=r10>:Hi</span></td>";
 $pg .= "<td class=hid data-hid=dr><span class=nb><$r id=srtreject data-sf=r11>:Rej</span></td>";
 $pg .= '<td class=dr>Block&nbsp;%</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtrate data-sf=r13>:Hash</span> Rate</td>";
 $pg .= "</tr></thead>\n";
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
			 $one = false, &$title, &$instances)
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
				'w_diffsta' => $ans['w_diffsta:'.$i],
				'w_diffdup' => $ans['w_diffdup:'.$i],
				'w_diffhi' => $ans['w_diffhi:'.$i],
				'w_diffrej' => $ans['w_diffrej:'.$i],
				'w_sharesta' => $ans['w_sharesta:'.$i],
				'w_sharedup' => $ans['w_sharedup:'.$i],
				'w_sharehi' => $ans['w_sharehi:'.$i],
				'w_sharerej' => $ans['w_sharerej:'.$i],
				'w_lastdiff' => $ans['w_lastdiff:'.$i],
				'w_active_diffacc' => $ans['w_active_diffacc:'.$i],
				'w_active_start' => $ans['w_active_start:'.$i],
				'w_uhr' => $uhr);

		$instances += $ans['w_instances:'.$i];
	}

	if ($srt)
		usort($all, 'workhashorder');

	foreach ($all as $arow)
	{
		$lst = $now - $arow['w_lastshare'];
		if ($old !== false && $lst > $old)
			continue;

		$lstacc = $now - $arow['w_lastshareacc'];

		if ((($offset) % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.htmlspecialchars($arow['workername']).'</td>';
		if ($arow['w_lastdiff'] > 0)
			$ld = difffmt($arow['w_lastdiff']);
		else
			$ld = '&nbsp;';
		$pg .= "<td class=dr>$ld</td>";

		$pg .= "<td class=dr data-srt=$lstacc>".howlongago($lstacc).'</td>';

		$shareacc = number_format($arow['w_shareacc'], 0);
		$totshare += $arow['w_shareacc'];
		$dacc = $arow['w_diffacc'];
		$diffacc = number_format($dacc, 0);
		$ds = round($dacc);
		$totdiff += $dacc;
		$pg .= "<td class=dr>$shareacc</td>";
		$pg .= "<td class=dr data-srt=$ds>$diffacc</td>";

		$acthr = '0';
		$acthrv = 0;
		$actstt = $arow['w_active_start'];
		if ($actstt <= 0 || ($now - $actstt) < 0)
			$actsin = '&nbsp;';
		else
		{
			$actsin = howmanyhrs($now - $actstt);
			$elapsed = $now - $actstt;
			if ($elapsed > 0)
			{
				$acthrv = $arow['w_active_diffacc'] *
						pow(2,32) / $elapsed;
				$acthr = dsprate($acthrv);
				$totshrate += $acthrv;
			}
		}
		$pg .= "<td class=dr data-srt=$acthrv>$acthr</td>";
		$pg .= "<td class=dr>$actsin</td>";

		$dinv = $arow['w_diffinv'];
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

		foreach(array('sta','dup','hi','rej') as $fld)
		{
			$shr = number_format($arow['w_share'.$fld]);
			$dif = $arow['w_diff'.$fld];
			$ddif = number_format($dif);
			$sdif = number_format($dif,0,'','');
			$pg .= "<td class=hid data-srt=$sdif data-hid=dr>$ddif/$shr</td>";
		}

		if ($blockacc <= 0)
			$blkpct = '&nbsp;';
		else
			$blkpct = number_format(100.0 * $dacc / $blockacc, 3) . '%';

		$pg .= "<td class=dr>$blkpct</td>";

		$uhr = $arow['w_uhr'];
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
			$totrate, $blockacc, $blockreward, $instances)
{
 $pg = '';
 $totshrate = dsprate($totshrate);
 $totrate = dsprate($totrate);
 if ($instances >= 0)
	$dspinst = " ($instances miners)";
 else
	$dspinst = '';

 if (($offset % 2) == 0)
	$row = 'even';
 else
	$row = 'odd';
 $pg .= "<tfoot><tr class=$row><td class=dl colspan=3>Total: $offset$dspinst</td>";
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
 $pg .= "<td class=hid colspan=4 data-hid=dr>&nbsp;</td>";
 $pg .= "<td class=dr>$blkpct</td>";
 $pg .= "<td class=dr>$totrate</td></tr></tfoot>\n";
 return $pg;
}
#
function doworker($data, $user)
{
 $title = '';

 $pg = worktable();

 $totshare = 0;
 $totdiff = 0;
 $totshrate = 0;
 $totinvalid = 0;
 $totrate = 0;
 $offset = 0;
 $blockacc = 0;
 $blockreward = 0;
 $instances = 0;

 $pg .= worktitle($data, $user);
 $pg .= '<tbody>';
 $pg .= workuser($data, $user, $offset, $totshare, $totdiff, $totshrate,
			$totinvalid, $totrate, $blockacc, $blockreward,
			false, true, true, $title, $instances);
 $pg .= '</tbody>';
 $pg .= worktotal($offset, $totshare, $totdiff, $totshrate, $totinvalid,
			$totrate, $blockacc, $blockreward, $instances);

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
