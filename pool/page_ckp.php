<?php
#
function stnum($num)
{
 $b4 = '';
 $af = '';
 $fmt = number_format($num, 0);
 if ($num > 99999999)
	$b4 = '<span class=urg>';
 else if ($num > 9999999)
	$b4 = '<span class=warn>';
 if ($b4 != '')
	$af = '</span>';
 return $b4.$fmt.$af;
}
#
function dockp($data, $user)
{
 $pg = '<h1>CKPool</h1>';

 $msg = msgEncode('stats', 'stats', array(), $user);
 $rep = sendsockreply('stats', $msg);
 if ($rep == false)
	$ans = array();
 else
	$ans = repDecode($rep);

 $pg .= 'TotalRAM: '.stnum($ans['totalram']).'<br>';
 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= '<thead><tr class=title>';
 $pg .= '<td class=dl>Name</td>';
 $pg .= '<td class=dr>Initial</td>';
 $pg .= '<td class=dr>Allocated</td>';
 $pg .= '<td class=dr>In&nbsp;Store</td>';
 $pg .= '<td class=dr>RAM</td>';
 $pg .= '<td class=dr>RAM2</td>';
 $pg .= '<td class=dr>Cull</td>';
 $pg .= "</tr></thead>\n";
 if ($ans['STATUS'] == 'ok')
 {
	$pg .= '<tbody>';
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.$ans['name:'.$i].'</td>';
		$pg .= '<td class=dr>'.stnum($ans['initial:'.$i]).'</td>';
		$pg .= '<td class=dr>'.stnum($ans['allocated:'.$i]).'</td>';
		$pg .= '<td class=dr>'.stnum($ans['instore:'.$i]).'</td>';
		$pg .= '<td class=dr>'.stnum($ans['ram:'.$i]).'</td>';
		$pg .= '<td class=dr>'.stnum($ans['ram2:'.$i]).'</td>';
		$pg .= '<td class=dr>'.stnum($ans['cull:'.$i]).'</td>';
		$pg .= "</tr>\n";
	}
	$pg .= '</tbody>';
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_ckp($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dockp', $page, $menu, $name, $user);
}
#
?>
