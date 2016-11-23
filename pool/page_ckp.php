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
 $pg = '<h1>CKDB</h1>';

 $msg = msgEncode('stats', 'stats', array(), $user);
 $rep = sendsockreply('stats', $msg);
 if ($rep == false)
	$ans = array();
 else
	$ans = repDecode($rep);

 addSort();
 $r = "input type=radio name=srt onclick=\"sott('ckpsrt',this);\"";
 $pg .= 'TotalRAM: '.stnum($ans['totalram']).'<br>';
 $pg .= "<table cellpadding=0 cellspacing=0 border=0>\n";
 $pg .= '<thead><tr class=title>';
 $pg .= "<td class=dl><span class=nb>Name:<$r id=srtname data-sf=s0></span></td>";
 $pg .= '<td class=dr>Initial</td>';
 $pg .= "<td class=dr><span class=nb><$r id=srtalloc data-sf=r2>:Alloc</span></td>";
 $pg .= "<td class=dr><span class=nb><$r id=srtstore data-sf=r3>:In&nbsp;Store</span></td>";
 $pg .= "<td class=dr><span class=nb><$r id=srtram data-sf=r4>:RAM</span></td>";
 $pg .= "<td class=dr><span class=nb><$r id=srtram2 data-sf=r5>:RAM2</span></td>";
 $pg .= "<td class=dr><span class=nb><$r id=srtcull data-sf=r6>:Cull</span></td>";
 $pg .= "<td class=dr><span class=nb><$r id=srtlim data-sf=r7>:Limit</span></td>";
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
		$pg .= "<td class=dl data-srt='".$ans['name:'.$i]."'>".$ans['name:'.$i].'</td>';
		$pg .= '<td class=dr>'.stnum($ans['initial:'.$i]).'</td>';
		$pg .= "<td class=dr data-srt='".$ans['allocated:'.$i]."'>".stnum($ans['allocated:'.$i]).'</td>';
		$pg .= "<td class=dr data-srt='".$ans['instore:'.$i]."'>".stnum($ans['instore:'.$i]).'</td>';
		$pg .= "<td class=dr data-srt='".$ans['ram:'.$i]."'>".stnum($ans['ram:'.$i]).'</td>';
		$pg .= "<td class=dr data-srt='".$ans['ram2:'.$i]."'>".stnum($ans['ram2:'.$i]).'</td>';
		$pg .= "<td class=dr data-srt='".$ans['cull:'.$i]."'>".stnum($ans['cull:'.$i]).'</td>';
		$pg .= "<td class=dr data-srt='".$ans['cull_limit:'.$i]."'>".stnum($ans['cull_limit:'.$i]).'</td>';
		$pg .= "</tr>\n";
	}
	$pg .= '</tbody>';
 }
 $pg .= "</table>\n";
 $pg .= "<script type='text/javascript'>\n";
 $pg .= "sotc('ckpsrt','srtram');</script>\n";

 return $pg;
}
#
function show_ckp($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dockp', $page, $menu, $name, $user);
}
#
?>
