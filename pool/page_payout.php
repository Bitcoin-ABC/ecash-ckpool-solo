<?php
#
function dopayout($data, $user)
{
 $pg = '<h1>Payouts</h1>';
 $pg .= '<table width=75% cellpadding=0 cellspacing=0 border=0><tr><td class=dc>';
 $pg .= "<p class=dl>We use PPLNS (pay per last N shares) with a novel fee structure.<br>
That is, a maximum of 2.5% and decreases with the hashrate contributed by the mining operator.<br>
(see table below).<br>
The N value used for PPLNS is the network difficulty when a block is found.</p>";
 $pg .= "<table cellpadding=5 width=100% border=1>
<tr><td class=dc><b>Tier</b></td><td class=dc><b>Hashrate (% of network)</b></td><td class=dc><b>Fee %</b></td></tr>
<tr><td class=dc>1</td><td class=dc>0 - 0.01</td><td class=dc>2.5</td></tr>
<tr><td class=dc>2</td><td class=dc>0.01 - 0.1</td><td class=dc>2</td></tr>
<tr><td class=dc>3</td><td class=dc>0.1 - 1</td><td class=dc>1.5</td></tr>
<tr><td class=dc>4</td><td class=dc>1+</td><td class=dc>1</td></tr>
</table>
<p class=dl>Fees are applied to each tier for each user. Fees are applied to the full block amount, plus transaction fees.<br>
The hashrate used in the fee calculation is the hashrate recorded during the pplns window: difficulty accepted/time.<br>
A flat rate of 0.5% is reserved for further development, with an initial focus on ckpool capability expansion.</p>";
 $pg .= '</td></tr></table>';
 return $pg;
}
#
function show_payout($page, $menu, $name, $user)
{
 gopage(NULL, 'dopayout', $page, $menu, $name, $user);
}
#
?>
