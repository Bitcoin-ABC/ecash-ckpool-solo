<?php
#
include_once('page_blocks.php');
#
function dopblocks($data, $user)
{
 return doblocks($data, null);
}
#
function show_pblocks($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dopblocks', $page, $menu, $name, $user);
}
#
?>
