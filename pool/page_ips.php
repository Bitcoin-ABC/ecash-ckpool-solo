<?php
#
function doips($data, $user)
{
 $pg = '<h1>Event IP Information</h1>';

 $ans = eventCmd($user, array('action' => 'ips'));

 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= '<thead><tr class=title>';
 $pg .= '<td class=dr>#</td>';
 $pg .= '<td class=dl>Group</td>';
 $pg .= '<td class=dl>IP</td>';
 $pg .= '<td class=dl>Name</td>';
 $pg .= '<td class=dr>Is?</td>';
 $pg .= '<td class=dr>Lifetime</td>';
 $pg .= '<td class=dr>Log</td>';
 $pg .= '<td class=dl>Desc</td>';
 $pg .= '<td class=dr>UTC</td>';
 $pg .= "</tr></thead>\n";
 if ($ans['STATUS'] == 'ok')
 {
	$pg .= '<tbody>';
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$j = $i+1;
		$pg .= "<tr class=$row>";
		$pg .= "<td class=dr>$j</td>";
		$pg .= '<td class=dl>'.$ans['group:'.$i].'</td>';
		$pg .= '<td class=dl>'.$ans['ip:'.$i].'</td>';
		$pg .= '<td class=dl>'.$ans['eventname:'.$i].'</td>';
		$pg .= '<td class=dr>'.$ans['is_event:'.$i].'</td>';
		$pg .= '<td class=dr>'.$ans['lifetime:'.$i].'</td>';
		$pg .= '<td class=dr>'.$ans['log:'.$i].'</td>';
		$pg .= '<td class=dl>'.$ans['description:'.$i].'</td>';
		$pg .= '<td class=dr>'.gmdate('j/M H:i:s',$ans['createdate:'.$i]).'</td>';
		$pg .= "</tr>\n";
	}
	$pg .= '</tbody>';
 }
 $pg .= "</table>\n";

 return $pg;
}
#
function show_ips($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doips', $page, $menu, $name, $user);
}
#
?>
