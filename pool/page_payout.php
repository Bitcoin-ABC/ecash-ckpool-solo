<?php
#
function dopayout($data, $user)
{
 $pg = '<h1>Payouts</h1>';
 $pg .= '<table width=75% cellpadding=0 cellspacing=0 border=0>';
 $pg .= '<tr><td class=dc>';
 $pg .= 'We use PPLNS (pay per last N shares)<br>';
 $pg .= 'Pool fee is 1.5%<br>';
 $pg .= 'The N value used for PPLNS is the network difficulty';
 $pg .= ' when a block is found.';
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
