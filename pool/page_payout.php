<?php
#
function dopayout($data, $user)
{
 $pg = '<h1>Payouts</h1>';
 $pg .= '<table width=75% cellpadding=0 cellspacing=0 border=0>';
 $pg .= '<tr><td class=dc>';
 $pg .= 'We use PPLNS (pay per last N shares)<br><br>';
 $pg .= 'The N value used for PPLNS is 5 times the network difficulty';
 $pg .= ' when a block is found,<br>';
 $pg .= 'but includes the full shift at the start and end of the range,<br>';
 $pg .= 'so it usually will be a bit more than 5N.<br><br>';
 $pg .= 'Shifts are ~50min long, however, when we find any pool blocks<br>';
 $pg .= 'the current shift ends at the point the block was found.<br>';
 $pg .= 'A ckpool restart will also start a new shift.<br><br>';
 $pg .= 'Transaction fees are included in the miner payout.<br>';
 $pg .= 'Pool fee is 0.9% of the total.<br>';
 $pg .= '</td></tr></table>';
 return $pg;
}
#
function show_payout($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dopayout', $page, $menu, $name, $user);
}
#
?>
