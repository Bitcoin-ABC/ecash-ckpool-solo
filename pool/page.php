<?php
#
global $site_title;
global $page_title;
global $page_scripts;
#
$site_title = 'CKPool';
$page_title = $site_title;
$page_scripts = '';
#
global $dont_trm;
$dont_trm = false;
#
// work out the page from ?k=page
function getPage()
{
 $uri = $_SERVER["REQUEST_URI"];

 $names = explode('k=', trim($uri));
 if (count($names) < 2)
	return '';

 $vals = explode('&', trim($names[1]));
 if ($count($vals) < 1)
	return '';

 return trim($vals[0]);
}
#
function addScript($script)
{
 global $page_scripts;

 if ($script != null and trim($script) != '')
 {
	if ($page_scripts == '')
		$page_scripts = "<script type='text/javascript'><!--\n";

	$page_scripts .= trim($script);
 }
}
#
function makeLink($page, $rest = '')
{
 if ($page != '')
	$page = '?k='.$page;
 $href = "<a href='index.php$page'";
 if ($rest != '')
	$href .= " $rest";
 $href .= '>';

 return $href;
}
#
function dotrm($html, $dontdoit)
{
 if ($dontdoit === true)
	return $html;
 else
	return preg_replace('/ *\n */', '', $html);
}
#
function trm($html)
{
 global $dont_trm;

 return dotrm($html, $dont_trm);
}
#
function trm_force($html)
{
 return dotrm($html, false);
}
#
function pghead($script_marker, $name)
{
 global $page_title;

 $head = "<!DOCTYPE html>\n";

 $head .= "<html><head><title>$page_title$name</title><meta content='text/html; charset=iso-8859-1' http-equiv='Content-Type'>";

 $head .= "<style type='text/css'>
form {display: inline-block;}
html, body {height: 100%; font-family:Arial, Verdana, sans-serif; font-size:12pt; background-color:#eff; text-align: center;}
.page {min-height: 100%; height: auto !important; height: 100%; margin: 0 auto -50px; position: relative;}
div.jst {color:red; background-color: #ffa; font-weight: font-size: 8; bold; border-style: solid; border-width: 2px; vertical-align: top;}
div.topd {background-color:#cff; border-color: #cff; border-style: solid; border-width: 9px;}
span.topdes {color:blue;}
span.topwho {color:black; font-weight: bold; margin-right: 8px;}
span.topdat {margin-left: 8px; margin-right: 24px; color:green; font-weight: bold;}
span.login {float: right; margin-left: 8px; margin-right: 24px;}
span.hil {color:blue;}
span.warn {color:orange; font-weight:bold;}
span.urg {color:red; font-weight:bold;}
#n42 {margin:0; position: relative; color:#fff; background:#07e;}
#n42 a {color:#fff; text-decoration:none; margin: 4px;}
#n42 td {min-width: 100px; float: left; vertical-align: top; padding: 2px;}
#n42 td.navboxr {float: right;}
#n42 td.nav {position: relative;}
#n42 div.sub {left: 0px; z-index: 42; position: absolute; visibility: hidden;}
#n42 td.ts {border-width: 1px; border-color: #02e; border-style: solid none none none;}
#n42 td.nav:hover {background:#09e;}
#n42 td.nav:hover div.sub {background:#07e; visibility: visible;}
h1 {margin-top: 20px; float:middle; font-size: 20px;}
.foot, .push {height: 50px; font-size: 10pt;}
.title {background-color: #909090;}
.even {background-color: #cccccc;}
.odd {background-color: #a8a8a8;}
.dl {text-align: left; padding: 2px 8px;}
.dr {text-align: right; padding: 2px 8px;}
.dc {text-align: center; padding: 2px 8px;}
.dls {text-align: left; padding: 2px 8px; text-decoration:line-through; font-weight:lighter; }
.drs {text-align: right; padding: 2px 8px; text-decoration:line-through; font-weight:lighter; }
.dcs {text-align: center; padding: 2px 8px; text-decoration:line-through; font-weight:lighter; }
</style>\n";

 $head .= '<meta name="robots" content="noindex">';

 $head .= $script_marker; // where to put the scripts

 $head .= '</head>';

 return $head;
}
#
function pgtop($dotop, $user, $douser)
{
 global $site_title;

 $info = homeInfo($user);
 $phr = '?THs';
 $plb = '?';
 $nlb = '?';
 $pac = '0';
 $per = '0';
 $uhr = '?GHs';
 $u1hr = '';
 if ($info !== false)
 {
	$now = time();

	if (isset($info['p_hashrate5m']))
		$phr = $info['p_hashrate5m'];

	if (isset($info['p_elapsed'])
	and isset($info['p_hashrate1hr'])
	and $info['p_elapsed'] > 3600)
		$phr = $info['p_hashrate1hr'];

	if ($phr == '?')
		$phr = '?THs';
	else
	{
		$phr /= 10000000;
		if ($phr < 100000)
			$phr = (round($phr)/100).'GHs';
		else
			$phr = (round($phr/1000)/100).'THs';
	}

	if (isset($info['lastblock']))
	{
		$plb = $info['lastblock'];
		if ($plb != '?')
		{
			$sec = $now - $plb;
			if ($sec < 60)
				$plb = $sec.'s';
			else
			{
				if ($sec < 3600)
				{
					$min = round($sec / 60);
					$plb = $min.'m';
				}
				else
				{
					$min = round($sec / 60);
					$hr = round($min / 60);
					$min -= ($hr * 60);
					$plb = $hr.'h';
					if ($min > 0)
						$plb .= ' '.$min.'m';
				}
			}
		}
	}

	if (isset($info['lastbc']))
	{
		$nlb = $info['lastbc'];
		if ($nlb != '?')
		{
			$sec = $now - $nlb;
			$min = round($sec / 60);
			$nlb = $min.'m';
			$s = $sec - $min * 60;
			if ($s > 0)
				$nlb .= " ${s}s";
		}
	}

	if (isset($info['blockacc']))
	{
		$acc = $info['blockacc'];
		$pac = number_format($acc, 0);
		if (isset($info['currndiff']))
		{
			$cur = $info['currndiff'];
			if ($cur != '?' && $cur > 0.0)
				$pac .= ' ('.number_format(100.0*$acc/$cur, 2).'%)';
		}
	}

	if (isset($info['blockerr']))
		$per = number_format($info['blockerr'], 0);

	if (isset($info['u_hashrate5m']))
	{
		$uhr = $info['u_hashrate5m'];
		if ($uhr == '?')
			$uhr = '?GHs';
		else
		{
			$uhr /= 10000000;
			if ($uhr < 100000)
				$uhr = (round($uhr)/100).'GHs';
			else
				$uhr = (round($uhr/1000)/100).'THs';
		}
	}

	if (isset($info['u_hashrate1hr'])
	and isset($info['u_elapsed'])
	and $info['u_elapsed'] > 3600)
	{
		$u1hr = $info['u_hashrate1hr'];
		if ($u1hr == '?')
			$u1hr = '';
		else
		{
			$u1hr /= 10000000;
			if ($u1hr < 100000)
				$u1hr = '/'.(round($u1hr)/100).'GHs';
			else
				$u1hr = '/'.(round($u1hr/1000)/100).'THs';

			if (substr($u1hr, -3) == substr($uhr, -3))
				$uhr = substr($uhr, 0, -3);
		}
	}
 }

 addscript("function jst(){document.getElementById('jst').style.visibility='hidden';}");
 $top = "<div class=jst id=jst>&nbsp;Javascript isn't enabled.";
 $top .= " You need to enable javascript to use";
 $top .= " the $site_title web site.</div>";
 $top .= '<div class=topd>';
 if ($dotop === true)
 {
	$top .= '<table cellpadding=0 cellspacing=0 border=0 width=100%><tr><td>';
	$top .= '<span class=topdes>CKPool:</span>';
	$top .= "<span class=topdat>$phr</span>";
	$top .= '<br>';
	$top .= '<span class=topdes>Shares:</span>';
	$top .= "<span class=topdat>$pac</span>";
	$top .= '</td><td>';
	$top .= '<span class=topdes>Pool, Last Block:</span>';
	$top .= "<span class=topdat>$plb</span>";
	$top .= '<br>';
	$top .= '<span class=topdes>Network, Last Block:</span>';
	$top .= "<span class=topdat>$nlb</span>";
	$top .= '</td><td>';
	$top .= '<span class=topdes>Users:</span>';
	$top .= '<span class=topdat>'.$info['users'].'</span>';
	$top .= '<br>';
	$top .= '<span class=topdes>Workers:</span>';
	$top .= '<span class=topdat>'.$info['workers'].'</span>';
	$top .= '</td><td>';

	if ($douser === true)
	{
		$top .= '<span class=login>';
		list($who, $whoid) = validate();
		if ($who == false)
		{
			$top .= "
<form action=index.php method=POST>
<table cellpadding=0 cellspacing=0 border=0><tr>
<td>User:</td><td><input type=text name=User size=10 value=''></td>
<td>&nbsp;<input type=submit name=Login value=Login></td></tr><tr>
<td>Pass:</td><td><input type=password name=Pass size=10 value=''></td>
<td>&nbsp;&nbsp;<input type=submit name=Register value=Register></td></tr></table>
</form>";
		}
		else
		{
			$top .= "
<span class=topwho>$who&nbsp;</span>
<span class=topdes>Hash Rate:</span>
<span class=topdat>$uhr$u1hr</span>
<form action=index.php method=POST>
&nbsp;<input type=submit name=Logout value=Logout>
</form>";
		}

		$top .= '</span>';
	}
 }
 else
	$top .= '&nbsp;';

 $top .= '</td></tr></table></div>';
 return $top;
}
#
function pgmenu($menus)
{
 if ($menus == NULL)
	$menus = array('Home'=>array('Home'=>''));
//	$menus = array('Home'=>array('Home'=>''),'gap'=>NULL,'Help'=>array('Help'=>'help'));

 $ret = "\n<table cellpadding=0 cellspacing=0 border=0 width=100% id=n42>";
 $ret .= '<tr><td width=100%>';
 $ret .= '<table cellpadding=0 cellspacing=0 border=0 width=100%>';
 $ret .= '<tr>';
 $side = '';
 foreach ($menus as $menu => $submenus)
 {
  if ($menu == 'gap')
  {
	$side = 'r';
	continue;
  }
  $ret .= "<td class=navbox$side><table cellpadding=0 cellspacing=0 border=0>";
  $first = true;
  foreach ($submenus as $submenu => $item)
  {
	if ($first == true)
	{
		$first = false;
		if ($submenu == $menu)
		{
			$ret .= "<tr><td class=nav>".makeLink($item)."$menu</a>";
			$ret .= '<div class=sub><table cellpadding=0 cellspacing=0 border=0 width=100%>';
			continue;
		}
		$ret .= "<tr><td class=nav><a>$menu</a>";
		$ret .= '<div class=sub><table cellpadding=0 cellspacing=0 border=0 width=100%>';
	}
	$ret .= "<tr><td class=ts>".makeLink($item,'class=as')."$submenu</a></td></tr>";
  }
  $ret .= '</table></div></td></tr></table></td>';
 }
 $ret .= "</tr></table></td></tr></table>\n";
 return $ret;
}
#
function pgbody($menu, $dotop, $user, $douser)
{
 $body = '<body onload="jst()">';
 $body .= '<div class=page>';
 $body .=  '<table border=0 cellpadding=0 cellspacing=0 width=100%>';

 $body .=   '<tr><td><center>';
 $body .=    '<table border=0 cellpadding=0 cellspacing=0 width=94%>';

 $body .=     '<tr><td>';
 $body .= pgtop($dotop, $user, $douser);
 $body .=     '</td></tr>';

 $body .=     '<tr><td>';
 $body .= pgmenu($menu);
 $body .=     '</td></tr>';

 $body .=     '<tr><td><div align=center>';

 return $body;
}
#
function pgfoot()
{
 $foot =      '</div></td></tr>';
 $foot .=    '</table>';
 $foot .=   '</center></td></tr>';
 $foot .=  '</table>';
 $foot .= '<div class=push></div></div>';
 $foot .= '<div class=foot><br>Copyright &copy; Kano 2014';
 $now = date('Y');
 if ($now != '2014')
	$foot .= "-$now";
 $foot .= '</div>';
 $foot .= "</body></html>\n";

 return $foot;
}
#
function gopage($data, $page, $menu, $name, $user, $ispage = true, $dotop = true, $douser = true)
{
 global $dbg;
 global $page_scripts;

 $dbg_marker = '[@dbg@]';
 $script_marker = '[@scripts@]';

 if ($dbg === true)
	$pg = $dbg_marker.'<br>';
 else
	$pg = '';

 if ($ispage == true)
	$pg .= $page($data, $user);
 else
	$pg .= $page;

// if (isset($_SESSION['logkey']))
//	unset($_SESSION['logkey']);

 $head = pghead($script_marker, $name);
 $body = pgbody($menu, $dotop, $user, $douser);
 $foot = pgfoot();

 if ($dbg === true)
	$pg = str_replace($dbg_marker, cvtdbg(), $pg);

 if ($page_scripts != '')
	$page_scripts .= "//-->\n</script>";

 $head = str_replace($script_marker, $page_scripts, $head);

 $all = $head;
 $all .= trm_force($body);
 $all .= trm($pg);
 $all .= trm_force($foot);

 usleep(100000);

 echo $all;

 exit(0);
}
?>
