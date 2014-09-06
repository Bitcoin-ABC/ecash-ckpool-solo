<?php
#
function dohelp($data, $user)
{
 return '<h1>Helpless</h1>Helpless';
}
#
function show_help($page, $menu, $name, $user)
{
 gopage(NULL, 'dohelp', $page, $menu, $name, $user);
}
#
?>
