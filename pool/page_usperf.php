<?php
#
function dousperf($data, $user)
{
 $ans = getShiftData($user);

 $iCrap = strpos($_SERVER['HTTP_USER_AGENT'],'iP');
 if ($iCrap)
	$vlines = false;
 else
	$vlines = true;

 $pg = '<h1>User Shift Performance</h1><br>';
 if ($ans['STATUS'] == 'ok' and $ans['DATA'] != '')
 {
	$pg .= "<div><input type=checkbox id=skey onclick='godrw()' checked>shift key&nbsp;";
	$pg .= "&nbsp;<input type=checkbox id=slines onclick='godrw()'";
	if ($vlines)
		$pg .= ' checked';
	$pg .= ">shift lines&nbsp;";
	$pg .= "&nbsp;<input type=checkbox id=tkey onclick='godrw()'>time key&nbsp;";
	$pg .= "&nbsp;<input type=checkbox id=tlines onclick='godrw()'>time lines&nbsp;";
	$pg .= "&nbsp;<input type=checkbox id=over onclick='godrw()'>key overlap&nbsp;";
	$pg .= "&nbsp;<input type=checkbox id=smooth onclick='godrw()'>smooth&nbsp;";
	$pg .= "&nbsp;<input type=checkbox id=zerob onclick='godrw()'>zero based</div>";
	$pg .= "<div id=can0><canvas id=can width=1 height=1>";
	$pg .= "A graph will show here if your browser supports html5/canvas";
	$pg .= "</canvas></div>\n";
	$data = str_replace(array("\\","'"), array("\\\\","\\'"), $ans['DATA']);
	$pg .= "<script src='/can.js'></script>\n";
	$pg .= "<script type='text/javascript'>function godrw(){dodrw('$data')};godrw();</script>\n";
 }

 return $pg;
}
#
function show_usperf($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dousperf', $page, $menu, $name, $user);
}
#
?>
