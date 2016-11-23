<?php
#
function doevents($data, $user)
{
 $pg = '<h1>Event Information</h1>';

 $wh = getparam('what', false);
 if (nuem($wh))
	$wh = '';

	$pg = '<br>'.makeForm('events')."
What: <input type=text name=what size=10 value='$wh'>
&nbsp;<input type=submit name=Get value=Get>
</form>";

 if ($wh == 'settings')
 {
	$ans = eventCmd($user, array('action' => 'settings'));

	$other = array('event_limits_hash_lifetime',
			'ovent_limits_ipc_factor');

	$pg .= "<br><br><table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= '<thead><tr class=title>';
	$pg .= '<td class=dr>#</td>';
	$pg .= '<td class=dl>Name</td>';
	$pg .= '<td class=dr>Value</td>';
	$pg .= "</tr></thead>\n";

	if ($ans['STATUS'] == 'ok')
	{
		$pg .= '<tbody>';
		$i = 0;
		foreach ($other as $name)
		{
			if (($i % 2) == 0)
				$row = 'even';
			else
				$row = 'odd';

			$i++;
			$pg .= "<tr class=$row>";
			$pg .= "<td class=dr>$i</td>";
			$pg .= "<td class=dl>$name</td>";
			$pg .= '<td class=dr>'.$ans[$name].'</td>';
			$pg .= "</tr>\n";
		}
		$pg .= '</tbody>';
	}
	$pg .= "</table>\n";

	$flds = array('enabled' => 'Ena',
			'user_low_time' => 'UserLo',
			'user_low_time_limit' => 'UserLoLim',
			'user_hi_time' => 'UserHi',
			'user_hi_time_limit' => 'UserHiLim',
			'ip_low_time' => 'IPLo',
			'ip_low_time_limit' => 'IPLoLim',
			'ip_hi_time' => 'IPHi',
			'ip_hi_time_limit' => 'IPHiLim',
			'lifetime' => 'Life');

	$pg .= "<br><br><table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= '<thead><tr class=title>';
	$pg .= '<td class=dr>#</td>';
	$pg .= '<td class=dl>Name</td>';
	foreach ($flds as $row => $nam)
		 $pg .= "<td class=dr>$nam</td>";
	$pg .= "</tr></thead>\n";

	if ($ans['STATUS'] == 'ok')
	{
		$pg .= '<tbody>';
		$names = array();
		foreach ($ans as $name => $value)
		{
			$ex = explode('_', $name, 2);
			if (count($ex) == 2 && isset($flds[$ex[1]]))
				$names[$ex[0]] = 1;
		}
		$i = 0;
		foreach ($names as $name => $one)
		{
			if (($i % 2) == 0)
				$row = 'even';
			else
				$row = 'odd';

			$i++;
			$pg .= "<tr class=$row>";
			$pg .= "<td class=dr>$i</td>";
			$pg .= "<td class=dl>$name</td>";
			foreach ($flds as $fld => $nam)
				$pg .= '<td class=dr>'.$ans[$name.'_'.$fld].'</td>';
			$pg .= "</tr>\n";
		}
		$pg .= '</tbody>';
	}
	$pg .= "</table>\n";
 }

 if ($wh == 'all' || $wh == 'user' || $wh == 'ip' || $wh == 'ipc' || $wh == 'hash')
 {
	$ans = eventCmd($user, array('action' => 'events', 'list' => $wh));

	$pg .= "<br><br><table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= '<thead><tr class=title>';
	$pg .= '<td class=dr>#</td>';
	$pg .= '<td class=dl>List</td>';
	$pg .= '<td class=dr>ID</td>';
	$pg .= '<td class=dl>IDName</td>';
	$pg .= '<td class=dl>User</td>';
	$pg .= '<td class=dr>IP</td>';
	$pg .= '<td class=dr>IPc</td>';
	$pg .= '<td class=dr>Hash</td>';
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
			$pg .= '<td class=dl>'.$ans['list:'.$i].'</td>';
			$pg .= '<td class=dr>'.$ans['id:'.$i].'</td>';
			$pg .= '<td class=dl>'.$ans['idname:'.$i].'</td>';
			$pg .= '<td class=dl>'.$ans['user:'.$i].'</td>';
			$pg .= '<td class=dr>'.isans($ans, 'ip:'.$i).'</td>';
			$pg .= '<td class=dr>'.isans($ans, 'ipc:'.$i).'</td>';
			$pg .= '<td class=dr>'.isans($ans, 'hash:'.$i).'</td>';
			$pg .= '<td class=dr>'.gmdate('j/M H:i:s',$ans['createdate:'.$i]).'</td>';
			$pg .= "</tr>\n";
		}
		$pg .= '</tbody>';
	}
	$pg .= "</table>\n";
 }

 if ($wh == 'ovents')
 {
	$ans = eventCmd($user, array('action' => 'ovents'));

	$pg .= "<br><br><table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= '<thead><tr class=title>';
	$pg .= '<td class=dr>#</td>';
	$pg .= '<td class=dl>Key</td>';
	$pg .= '<td class=dr>ID</td>';
	$pg .= '<td class=dl>IDName</td>';
	$pg .= '<td class=dr>Hour UTC</td>';
	$pg .= '<td class=dl>Count</td>';
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
			$pg .= '<td class=dl>'.$ans['key:'.$i].'</td>';
			$pg .= '<td class=dr>'.$ans['id:'.$i].'</td>';
			$pg .= '<td class=dl>'.$ans['idname:'.$i].'</td>';
			$pg .= '<td class=dr>'.gmdate('j/M H:i:s',$ans['hour:'.$i]*3600).'</td>';
			$co = '';
			for ($k = 0; $k < 60; $k++)
			{
				if ($k < 10)
					$min = '0' . $k;
				else
					$min = $k;
				if (isset($ans["min$min:$i"]))
				{
					if ($co != '')
						$co .= ' ';
					$co .= "$min=".$ans["min$min:$i"];
				}
			}
			$pg .= "<td class=dl>$co</td>";
			$pg .= "</tr>\n";
		}
		$pg .= '</tbody>';
	}
	$pg .= "</table>\n";
 }

 return $pg;
}
#
function show_events($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doevents', $page, $menu, $name, $user);
}
#
?>
