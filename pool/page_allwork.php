<?php
#
include_once('page_workers.php');
#
function doallwork($data, $user)
{
 $pg = '<h1>All Workers</h1>';

 $pg .= worktable();

 $totshare = 0;
 $totdiff = 0;
 $totshrate = 0;
 $totinvalid = 0;
 $totrate = 0;
 $offset = 0;
 $blockacc = 0;
 $blockreward = 0;

 $pg .= worktitle($data, $user);

 $ans = getAllUsers($user);
 if ($ans['STATUS'] == 'ok')
 {
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		$pg .= workuser($data, $ans['username:'.$i],
				$offset, $totshare, $totdiff,
				$totshrate, $totinvalid, $totrate,
				$blockacc, $blockreward, 3600);
	}
 }

 $pg .= worktotal($offset, $totshare, $totdiff, $totshrate, $totinvalid,
		  $totrate, $blockacc, $blockreward);

 $pg .= "</table>\n";

 return $pg;
}
#
function show_allwork($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doallwork', $page, $menu, $name, $user);
}
#
?>
