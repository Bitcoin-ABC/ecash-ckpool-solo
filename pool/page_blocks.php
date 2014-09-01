<?php
#
function doblocks($data, $user)
{
 $pg = '<h1>Blocks</h1>';

 $rep = getBlocks($user);
 $ans = repDecode($rep);

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dl>Height</td>";
 $pg .= "<td class=dl>Who</td>";
 $pg .= "<td class=dr>Reward</td>";
 $pg .= "<td class=dc>When</td>";
 $pg .= "<td class=dr>Status</td>";
 $pg .= "</tr>\n";
 if ($ans['STATUS'] == 'ok')
 {
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$ex = '';
		$stat = $ans['status'.$i];
		if ($stat == 'Orphan')
			$ex = 's';
		if ($stat == '1-Confirm')
			$stat = 'Conf';

		$pg .= "<tr class=$row>";
		$pg .= "<td class=dl$ex>".$ans['height'.$i].'</td>';
		$pg .= "<td class=dl$ex>".$ans['workername'.$i].'</td>';
		$pg .= "<td class=dr$ex>".btcfmt($ans['reward'.$i]).'</td>';
		$pg .= "<td class=dl$ex>".gmdate('Y-m-d H:i:s+00', $ans['firstcreatedate'.$i]).'</td>';
		$pg .= "<td class=dr$ex>".$stat.'</td>';
		$pg .= "</tr>\n";
	}
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_blocks($menu, $name, $user)
{
 gopage(NULL, 'doblocks', $menu, $name, $user);
}
#
?>
