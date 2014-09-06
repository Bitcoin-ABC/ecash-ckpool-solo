<?php
#
function dopayments($data, $user)
{
 $pg = '<h1>Payments</h1>';

 $ans = getPayments($user);

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= "<tr class=title>";
 $pg .= "<td class=dl>Date</td>";
 $pg .= "<td class=dl>Address</td>";
 $pg .= "<td class=dr>BTC</td>";
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

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.$ans['paydate:'.$i].'</td>';
		$pg .= '<td class=dl>'.$ans['payaddress:'.$i].'</td>';
		$pg .= '<td class=dr>'.btcfmt($ans['amount:'.$i]).'</td>';
		$pg .= "</tr>\n";
	}
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_payments($page, $menu, $name, $user)
{
 gopage(NULL, 'dopayments', $page, $menu, $name, $user);
}
#
?>
