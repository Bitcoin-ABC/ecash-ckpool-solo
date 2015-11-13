<?php
#
function blocksorder($a, $b)
{
 if ($b['blocks'] != $a['blocks'])
	return $b['blocks'] - $a['blocks'];
 else
 {
	if ($b['diffacc'] != $a['diffacc'])
		return $a['diffacc'] - $b['diffacc'];
	else
		return strcasecmp($a['username'], $b['username']);
 }
}
#
function douserinfo($data, $user)
{
 $sall = ($user == 'Kano');

 $ans = getUserInfo($user);

 $pg = '<h1>Block Acclaim</h1>';
 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dl>User</td>";
 $pg .= "<td class=dr>Blocks</td>";
 if ($sall)
 {
	$pg .= "<td class=dr>Diff</td>";
	$pg .= "<td class=dr>Avg</td>";
 }
 $pg .= "</tr>\n";

 if ($ans['STATUS'] == 'ok')
 {
	$all = array();
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if ($sall)
			$diffacc = $ans['diffacc:'.$i];
		else
			$diffacc = 0;

		$all[] = array('blocks' => $ans['blocks:'.$i],
				'username' => $ans['username:'.$i],
				'diffacc' => $diffacc);
	}
	usort($all, 'blocksorder');

	for ($i = 0; $i < $count; $i++)
	{
		$bl = $all[$i]['blocks'];
		if ($sall == false && $bl < 1)
			break;

		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$un = htmlspecialchars($all[$i]['username']);
		$pg .= "<td class=dl>$un</td>";
		$pg .= "<td class=dr>$bl</td>";
		if ($sall)
		{
			$diffacc = $all[$i]['diffacc'];
			$pg .= '<td class=dr>'.difffmt($diffacc).'</td>';
			if ($bl == 0)
				$bl = 1;
			$pg .= '<td class=dr>'.difffmt($diffacc/$bl).'</td>';
		}
		$pg .= "</tr>\n";
	}
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_userinfo($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'douserinfo', $page, $menu, $name, $user);
}
#
?>
