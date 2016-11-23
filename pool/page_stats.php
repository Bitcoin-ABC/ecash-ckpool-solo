<?php
#
function allusersort($a, $b)
{
 $cmp = $b['u_hashrate5m'] - $a['u_hashrate5m'];
 if ($cmp != 0)
	return $cmp;
 return $a['userid'] - $b['userid'];
}
#
function dostats($data, $user)
{
 $pg = '<h1>Pool Stats</h1>';

 if (isset($data['info']) && $data['info'] !== false)
 {
	$info = $data['info'];

	$pe = false;
	if (isset($info['p_elapsed']))
	{
		$dspel = howlongago($info['p_elapsed']);
		$pg .= "Pool&nbsp;Uptime:&nbsp;$dspel";
		$pe = true;
	}

	if (isset($info['ckdb_elapsed']))
	{
		if ($pe)
			$pg .= '&emsp;';
		$dspel = howlongago($info['ckdb_elapsed']);
		$pg .= "CKDB&nbsp;Uptime:&nbsp;$dspel";
	}

	$dsp = '?THs';
	$dsp5m = '?THs';
	$dsp1hr = '?THs';
	$dsp24hr = '?THs';

	if (isset($info['p_hashrate']))
	{
		$hr = $info['p_hashrate'];
		if ($hr != '?')
			$dsp = dsprate($hr);
	}

	if (isset($info['p_hashrate5m']))
	{
		$hr = $info['p_hashrate5m'];
		if ($hr != '?')
			$dsp5m = dsprate($hr);
	}

	if (isset($info['p_hashrate1hr']))
	{
		$hr = $info['p_hashrate1hr'];
		if ($hr != '?')
			$dsp1hr = dsprate($hr);
	}

	if (isset($info['p_hashrate24hr']))
	{
		$hr = $info['p_hashrate24hr'];
		if ($hr != '?')
			$dsp24hr = dsprate($hr);
	}

	$pg .= '<table cellpadding=8 cellspacing=0 border=0><tr>';
	$pg .= "<td>Pool Hashrate: $dsp</td>";
	$pg .= "<td>5m: $dsp5m</td>";
	$pg .= "<td>1hr: $dsp1hr</td>";
	$pg .= "<td>24hr: $dsp24hr</td>";
	$pg .= '</tr></table><br>';
 }

 $ans = getAllUsers($user);

 $pg .= "<table cellpadding=0 cellspacing=0 border=0>\n";
 $pg .= '<thead><tr class=title>';
 $pg .= '<td class=dl>Username</td>';
 $pg .= '<td class=dr>Hash Rate 5m</td>';
 $pg .= "</tr></thead>\n";
 if ($ans['STATUS'] == 'ok')
 {
	$pg .= '<tbody>';
	$all = array();
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		$all[] = array('username' => $ans['username:'.$i],
				'userid' => $ans['userid:'.$i],
				'u_hashrate5m' => $ans['u_hashrate5m:'.$i]);
	}

	usort($all, 'allusersort');

	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.htmlspecialchars($all[$i]['username']).'</td>';
		$uhr = $all[$i]['u_hashrate5m'];
		if ($uhr == '?')
			$dsp = '?GHs';
		else
			$dsp = dsprate($uhr);
		$pg .= "<td class=dr>$dsp</td>";
		$pg .= "</tr>\n";
	}
	$pg .= '</tbody>';
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_stats($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dostats', $page, $menu, $name, $user);
}
#
?>
