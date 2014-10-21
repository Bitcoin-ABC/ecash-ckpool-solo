<?php
#
@include_once('myindex.php');
#
function show_index($page, $menu, $name, $user)
{
 gopage(NULL, 'doindex', $page, $menu, $name, $user);
}
#
?>
