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
function makeForm($page)
{
 $form = '<form action=index.php method=POST>';
 if (strlen($page) > 0)
	$form .= "<input type=hidden name=k value=$page>";
 return $form;
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

 $iCrap = strpos($_SERVER['HTTP_USER_AGENT'],'iP');

 $head = "<!DOCTYPE html>\n";

 $head .= "<html><head><title>$page_title$name</title>";
 $head .= "<meta content='text/html; charset=iso-8859-1' http-equiv='Content-Type'>";
 $head .= "<meta content='IE=edge' http-equiv='X-UA-Compatible'>";
 $head .= "<meta content='width=device-width, initial-scale=1' name='viewport'>";

 $head .= "<script type='text/javascript'>\n";
 $head .= "function jst(){document.getElementById('jst').style.visibility='hidden';}\n";
 $head .= "window.onpaint=jst();\n</script>\n";

 $head .= "<style type='text/css'>
input {vertical-align: -2px;}
form {display: inline-block;}
html, body {height: 100%; font-family:Arial, Verdana, sans-serif; font-size:12pt; background-color:#eeffff; text-align: center; background-repeat: no-repeat; background-position: center;}
.page {min-height: 100%; height: auto !important; height: 100%; margin: 0 auto -50px; position: relative;}
div.jst {color:red; font-weight: bold; font-size: 8; text-align: center; vertical-align: top;}
div.accwarn {color:red; font-weight: bold; font-size: 8; text-align: center; vertical-align: top;}
div.topd {background-color:#cff; border-color: #cff; border-style: solid; border-width: 9px;}
.topdes {color:blue; text-align: right;}
.topdesl {color:blue; text-align: left;}
.topwho {color:black; font-weight: bold; margin-right: 8px;}
.topdat {margin-left: 8px; margin-right: 24px; color:green; font-weight: bold;}
span.login {float: right; margin-left: 8px; margin-right: 24px;}
span.hil {color:blue;}
span.user {color:green;}
span.addr {color:brown;}
span.warn {color:orange; font-weight:bold;}
span.urg {color:red; font-weight:bold;}
span.err {color:red; font-weight:bold; font-size:120%;}
span.alert {color:red; font-weight:bold; font-size:250%;}
input.tiny {width: 0px; height: 0px; margin: 0px; padding: 0px; outline: none; border: 0px;}
#n42 {margin:0; position: relative; color:#fff; background:#07e;}
#n42 a {color:#fff; text-decoration:none; padding: 6px; display:block;}
#n42 td {min-width: 100px; float: left; vertical-align: top; padding: 0px 2px;}
#n42 td.navboxr {float: right;}
#n42 td.nav {position: relative;}
#n42 td.ts {border-width: 1px; border-color: #02e; border-style: solid none none none;}";
if (!$iCrap)
{
 $head .= "
#n42 div.sub {left: 0px; z-index: 42; position: absolute; visibility: hidden;}
#n42 td.nav:hover {background:#09e;}
#n42 td.nav:hover div.sub {background:#07e; visibility: visible;}";
}
 $head .= "
h1 {margin-top: 20px; float:middle; font-size: 20px;}
.foot, .push {height: 50px; font-size: 10pt;}
.title {background-color: #909090;}
.even {background-color: #cccccc;}
.odd {background-color: #a8a8a8;}
.hid {display: none;}
.dl {text-align: left; padding: 2px 8px;}
.dr {text-align: right; padding: 2px 8px;}
.dc {text-align: center; padding: 2px 8px;}
.dls {text-align: left; padding: 2px 8px; text-decoration:line-through; font-weight:lighter; }
.drs {text-align: right; padding: 2px 8px; text-decoration:line-through; font-weight:lighter; }
.dcs {text-align: center; padding: 2px 8px; text-decoration:line-through; font-weight:lighter; }
.st0 {font-weight:bold; }
.st1 {color:red; font-weight:bold; }
.st2 {color:green; font-weight:bold; }
.st3 {color:blue; font-weight:bold; }
.fthi {color:red; font-size:7px; }
.ftlo {color:green; font-size:7px; }
.ft {color:blue; font-size:7px; }
</style>\n";

 $head .= '<meta name="robots" content="noindex">';

 $head .= $script_marker; // where to put the scripts

 $head .= '</head>';

 return $head;
}
#
function pgtop($info, $dotop, $user, $douser)
{
 global $site_title, $loginfailed;

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

//	if (isset($info['p_elapsed'])
//	and isset($info['p_hashrate1hr'])
//	and $info['p_elapsed'] > 3600)
//		$phr = $info['p_hashrate1hr'];

	if ($phr == '?')
		$phr = '?THs';
	else
		$phr = dsprate($phr);

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

	if (isset($info['lastblockheight']))
		$plb .= ' ('.$info['lastblockheight'].')';

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

	if (isset($info['lastheight']))
		$nlb .= ' ('.$info['lastheight'].')';

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
	{
		$rej = $info['blockerr'];
		$per = number_format($info['blockerr'], 0);
		if (isset($info['blockacc']) && ($acc+$rej) > 0)
			$per .= ' ('.number_format(100.0*$rej/($acc+$rej), 3).'%)';
	}

	if (isset($info['u_hashrate5m']))
	{
		$uhr = $info['u_hashrate5m'];
		if ($uhr == '?')
			$uhr = '?GHs';
		else
			$uhr = dsprate($uhr);
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
			$u1hr = '/'.dsprate($u1hr);

			// Remove the first XHs if they are the same
			if (substr($u1hr, -3) == substr($uhr, -3))
				$uhr = substr($uhr, 0, -3);
		}
	}
 }

 $top = "<div class=jst id=jst>&nbsp;Javascript isn't enabled.";
 $top .= " You need to enable javascript to use";
 $top .= " the $site_title web site.</div>";

 if ($loginfailed === true)
	$top .= '<div class=accwarn>Login Failed</div>';
 if (isset($info['u_nopayaddr']))
	$top .= '<div class=accwarn>Please set a payout address on your account!</div>';
 if (isset($info['u_noemail']))
	$top .= '<div class=accwarn>Please set an email address on your account!</div>';

 $top .= '<div class=topd>';
 if ($dotop === true)
 {
	$lh = ''; $ls = ''; $lw = '';
	if (isset($info['now']) && isset($info['lastsh'])
	&&  isset($info['lasthb']) && isset($info['lastwi']))
	{
		$lsn = $info['now'] - $info['lastsh'];
		$lhn = $info['now'] - $info['lasthb'];
		$lwn = $info['now'] - $info['lastwi'];
		if ($lsn < 8)
			$lsc = 'green.png';
		else
		{
			if ($lsn < 10)
				$lsc = 'orange.png';
			else
				$lsc = 'red.png';
		}
		if ($lhn < 5)
			$lhc = 'green.png';
		else
		{
			if ($lhn < 10)
				$lhc = 'orange.png';
			else
				$lhc = 'red.png';
		}
		if ($lwn < 36)
			$lwc = 'green.png';
		else
		{
			if ($lwn < 46)
				$lwc = 'orange.png';
			else
				$lwc = 'red.png';
		}
		$img1 = '<img border=0 src=/';
		$img2 = '>';
		$ls = $img1.$lsc.$img2;
		$lh = $img1.$lhc.$img2;
		$lw = $img1.$lwc.$img2;
	}
	$top .= '<table cellpadding=0 cellspacing=0 border=0 width=100%><tr><td>';
	$top .= '<table cellpadding=1 cellspacing=0 border=0>';
	$top .= "<tr><td class=topdes>$lh</td></tr>";
	$top .= "<tr><td class=topdes>$ls</td></tr>";
	$top .= "<tr><td class=topdes>$lw</td></tr></table>";
	$top .= '</td><td>';
	$top .= '<table cellpadding=1 cellspacing=0 border=0 width=100%>';
	$top .= '<tr><td class=topdes>CKPool:&nbsp;</td>';
	$top .= "<td class=topdat>&nbsp;$phr</td></tr>";
	$top .= '<tr><td class=topdes>Shares:&nbsp;</td>';
	$top .= "<td class=topdat>&nbsp;$pac</td></tr>";
	$top .= '<tr><td class=topdes>Invalid:&nbsp;</td>';
	$top .= "<td class=topdat>&nbsp;$per</td></tr></table>";
	$top .= '</td><td>';
	$top .= '<table cellpadding=1 cellspacing=0 border=0 width=100%>';
	$top .= '<tr><td class=topdes>Last&nbsp;</td>';
	$top .= '<td class=topdesl>Block</td></tr>';
	$top .= '<tr><td class=topdes>Pool:&nbsp;</td>';
	$top .= "<td class=topdat>&nbsp;$plb</td></tr>";
	$top .= '<tr><td class=topdes>Network:&nbsp;</td>';
	$top .= "<td class=topdat>&nbsp;$nlb</td></tr></table>";
	$top .= '</td><td>';
	$top .= '<table cellpadding=1 cellspacing=0 border=0 width=100%>';
	$top .= '<tr><td class=topdes>Users:&nbsp;</td>';
	$top .= '<td class=topdat>&nbsp;'.$info['users'].'</td></tr>';
	$top .= '<tr><td class=topdes>Workers:&nbsp;</td>';
	$top .= '<td class=topdat>&nbsp;'.$info['workers'].'</td></tr></table>';
	$top .= '</td><td>';

	if ($douser === true)
	{
		$top .= '<span class=login>';
		list($who, $whoid) = validate();
		if ($who == false)
		{
			$top .= makeForm('')."
<table cellpadding=0 cellspacing=0 border=0><tr><td>
<table cellpadding=0 cellspacing=0 border=0><tr>
<td>User:</td><td><input type=text name=User size=10 value=''></td>
</tr><tr>
<td>Pass:</td><td><input type=password name=Pass size=10 value=''></td>
</tr></table></td><td>
<table cellpadding=0 cellspacing=0 border=0><tr>
<td>&nbsp;<input type=submit name=Login value=Login></td></tr><tr>
<td>&nbsp;&nbsp;<input type=submit name=Register value='Register/Reset'></td></tr></table>
</td></tr></table></form>";
		}
		else
		{
			$extra = '';
			$first = substr($who, 0, 1);
			if (($first == '1' || $first == '3') && strlen($who) > 12)
			{
				$who = substr($who, 0, 11);
				$extra = '&#133;';
			}
			$top .= "
<span class=topwho>".htmlspecialchars($who)."$extra&nbsp;</span><br>
<span class=topdes>Hash&nbsp;Rate:</span>
<span class=topdat>$uhr$u1hr</span><br>";
			$top .= makeForm('')."
<input type=submit name=Logout value=Logout>
</form>";
		}

		$top .= '</span>';
	}
	$top .= '</td></tr></table>';
 }
 else
	$top .= '&nbsp;';

 $top .= '</div>';
 return $top;
}
#
function pgmenu($menus)
{
 $iCrap = strpos($_SERVER['HTTP_USER_AGENT'],'iP');

 $ret = "\n<table cellpadding=0 cellspacing=0 border=0 width=100% id=n42>";
 $ret .= '<tr><td width=100%>';
 $ret .= '<table cellpadding=0 cellspacing=0 border=0 width=100%>';
 $ret .= '<tr>';
 $side = '';
 foreach ($menus as $menu => $submenus)
 {
  if ($menu == 'Admin' && $submenus == null)
	continue;

  if ($menu == 'gap')
  {
	$side = 'r';
	continue;
  }
  if ($iCrap)
  {
   foreach ($submenus as $submenu => $item)
	$ret .= "<td class=nav>".makeLink($item)."$submenu</a></td>";
  }
  else
  {
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
   if ($first == false)
	$ret .= '</table></div></td></tr></table>';
   $ret .= '</td>';
  }
 }
 $ret .= "</tr></table></td></tr></table>\n";
 return $ret;
}
#
function pgbody($info, $page, $menu, $dotop, $user, $douser)
{
 $body = '<body onload="jst()"';
 if ($page == 'index')
	$body .= ' background=/BTC20.png';
 $body .= '><div class=page>';
 $body .=  '<table border=0 cellpadding=0 cellspacing=0 width=100%>';

 $body .=   '<tr><td><center>';
 $body .=    '<table border=0 cellpadding=0 cellspacing=0 width=94%>';

 $body .=     '<tr><td>';
 $body .= pgtop($info, $dotop, $user, $douser);
 $body .=     '</td></tr>';

 $body .=     '<tr><td>';
 $body .= pgmenu($menu);
 $body .=     '</td></tr>';

 $body .=     '<tr><td><div align=center>';

 return $body;
}
#
function pgfoot($info)
{
 $foot =      '</div></td></tr>';
 $foot .=    '</table>';
 $foot .=   '</center></td></tr>';
 $foot .=  '</table>';
 $foot .= '<div class=push></div></div>';
 $foot .= '<div class=foot><br>';
 if (is_array($info) && isset($info['sync']))
 {
  $sync = $info['sync'];
  if ($sync > 5000)
	$syc = 'hi';
  else
	$syc = 'lo';
  $syncd = number_format($sync);
  $foot .= "<span class=ft$syc>sync: $syncd</span> ";
 }
 $foot .= 'Copyright &copy; Kano 2014';
 $now = date('Y');
 if ($now != '2014')
	$foot .= "-$now";
 $foot .= ' <span class=ft>Z/s</span></div>';
 $foot .= "</body></html>\n";

 return $foot;
}
#
function gopage($info, $data, $pagefun, $page, $menu, $name, $user, $ispage = true, $dotop = true, $douser = true)
{
 global $dbg, $stt;
 global $page_scripts;

 $dbg_marker = '[@dbg@]';
 $script_marker = '[@scripts@]';

 if ($dbg === true)
	$pg = $dbg_marker.'<br>';
 else
	$pg = '';

 if ($info === NULL)
	$info = homeInfo($user);

 if ($ispage == true)
 {
	$both = array('info' => $info, 'data' => $data);
	$pg .= $pagefun($both, $user);
 }
 else
	$pg .= $pagefun;

// if (isset($_SESSION['logkey']))
//	unset($_SESSION['logkey']);

 $head = pghead($script_marker, $name);
 $body = pgbody($info, $page, $menu, $dotop, $user, $douser);
 $foot = pgfoot($info);

 if ($dbg === true)
	$pg = str_replace($dbg_marker, cvtdbg(), $pg);

 if ($page_scripts != '')
	$page_scripts .= "//-->\n</script>";

 $head = str_replace($script_marker, $page_scripts, $head);

 $all = $head;
 $all .= trm_force($body);
 $all .= trm($pg);

 if (isset($_SERVER["REQUEST_TIME_FLOAT"]))
	$elapsed = microtime(true) - $_SERVER["REQUEST_TIME_FLOAT"];
 else
	$elapsed = microtime(true) - $stt;

 $foot = trm_force(str_replace('Z/', number_format($elapsed, 4), $foot));

 usleep(100000);

 echo $all.$foot;

 exit(0);
}
?>
