<?php
#
function dopayments($data, $user)
{
 $bc = 'https://blockchain.info/address/';
 $addr1 = '1KzFJddTvK9TQWsmWFKYJ9fRx9QeSATyrT';

 $pg = '<h1>Payments</h1>';
 $pg .= 'The payout transactions on blockchain are here:';
 $pg .= " <a href='$bc$addr1' target=_blank>BTC</a><br><br>";

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
function show_payments($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dopayments', $page, $menu, $name, $user);
}
#
?>
