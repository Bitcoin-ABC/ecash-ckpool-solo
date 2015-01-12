<?php
#
@include_once('myindex.php');
#
function show_index($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doindex', $page, $menu, $name, $user);
}
#
?>
