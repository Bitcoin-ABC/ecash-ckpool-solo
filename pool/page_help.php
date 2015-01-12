<?php
#
function dohelp($data, $user)
{
 return '<h1>Helpless</h1>Helpless';
}
#
function show_help($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dohelp', $page, $menu, $name, $user);
}
#
?>
