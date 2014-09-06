<?php
#
function doindex($data, $user)
{
 $pg = '
<h1>CKPool</h1>
Welcome to CKPool
';
 return $pg;
}
#
function show_index($page, $menu, $name, $user)
{
 gopage(NULL, 'doindex', $page, $menu, $name, $user);
}
#
?>
