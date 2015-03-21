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
		$page_scripts = "<script type='text/javascript'>\n";

	$page_scripts .= trim($script);
 }
}
#
function addGBase()
{
 $g = "function hasCan(){var c0=document.getElementById('can0');c=document.getElementById('can');return !!(c0&&c&&c.getContext&&c.getContext('2d'));}
function sep(d){ans={};var ar=d.split('\\t');var l=ar.length;for(var i=0;i<l;i++){var e=ar[i].indexOf('=');ans[ar[i].substr(0,e)]=ar[i].substr(e+1)};return ans}
function dfmt(c,e){var d=new Date(e*1000);var DD,HH,MM;if(c['utc']){DD=d.getUTCDate();HH=d.getUTCHours();MM=d.getUTCMinutes()}else{DD=d.getDate();HH=d.getHours();MM=d.getMinutes()}var ans=''+DD+'/';if(HH<10){ans+='0'}ans+=''+HH+':';if(MM<10){ans+='0'}ans+=''+MM;return ans}
function gcn(n){var ans='',d=document.cookie;if(d){var c0=d.indexOf(n+'='),cs=d.indexOf(' '+n+'=');if(c0==0||cs>0){if(cs>0){c0=cs+1}var c=d.substr(c0).split(';',1);var e=c[0].indexOf('=');if(e>0){ans=c[0].substr(e+1)}}}return ans}
function scnv(n,v){var d = new Date();d.setTime(d.getTime()+(864*Math.pow(10,8)));document.cookie=n+'='+v+'; expires='+d.toUTCString()+'; path=/'}
function ccb(c,n){var e=document.getElementById(n);c[n]=(e&&e.checked)}
function gch(z,zm){if(z<0.5){return 0.5}if(z>(zm-0.5)){return(zm-0.5)}return z}
function gchx(c,x){return gch(x*c['xm']+c['xo'],c['ctx'].canvas.width)}
function gchy(c,y){return gch((1-y)*c['ym']+c['yo'],c['ctx'].canvas.height)}
function gx0(c){return -c['xo']/c['xm']};
function gy0(c){return -c['yo']/c['ym']};
function gto(c,xo,yo){c['xo']+=xo;c['yo']+=yo}
function gts(c,xs,ys){c['xm']*=xs;c['ym']*=ys}
function gtso(c,xs,ys){gto(c,c['xm']*(1.0-xs)/2.0,c['ym']*(1.0-ys)/2.0);gts(c,xs,ys)}
function gfs(c,bg){c['ctx'].fillStyle=bg}
function gss(c,fg){c['ctx'].strokeStyle=fg}
function glw(c,w){c['ctx'].lineWidth=w}
function gfz(c,x,y,ox,oy,t,co,a){gfs(c,co);c['ctx'].textAlign=a;c['ctx'].fillText(t,gchx(c,x)+ox,gchy(c,y)-oy)}
function gbe(c,x,y){c['ctx'].beginPath();c['ctx'].moveTo(gchx(c,x),gchy(c,y))}
function gln(c,x,y){c['ctx'].lineTo(gchx(c,x),gchy(c,y))}
function gct(c,x1,y1,x2,y2,x3,y3){c['ctx'].bezierCurveTo(gchx(c,x1),gchy(c,y1),gchx(c,x2),gchy(c,y2),gchx(c,x3),gchy(c,y3))}
function glm(c,x,y){c['ctx'].moveTo(gchx(c,x),gchy(c,y))}
function gle(c){c['ctx'].closePath()}
function gfl(c){c['ctx'].fill()}
function gst(c){c['ctx'].stroke()}
function gfi(c){gle(c);gst(c)}
function gbd(c){gbe(c,0,0);gln(c,1,0);gln(c,1,1);gln(c,0,1);gle(c);gfl(c);gst(c)}
function ggr(c,xs,ys,yt,xn,x0,x1,y0,y1,ar,nx,vx,vy,av){
gtso(c,xs,ys);
gss(c,'black');glw(c,1.5);
gbe(c,0,1);gln(c,0,0);gln(c,1,0);gst(c);
glw(c,0.2);
var hi=c['ctx'].measureText('M').width, wi=c['ctx'].measureText('1').width;
for(var i=0;i<11;i++){var y=i/10.0;gbe(c,-0.01,y);gln(c,1,y);gst(c);var t=''+(((y1-y0)*i/10+y0).toFixed(2));gfz(c,0,y,-wi,0,t,'black','end')}
gfz(c,gx0(c),0.55,wi,0,yt,'#0080ff','left');
var m=Math.round(0.5+xn/20.0);
var f=1;
for(var i=0;i<xn;i++){var n=ar[nx+i];var x=ar[vx+i];var xo=(x-x0)/(x1-x0);if(c['skey']&&(i<(xn-1))&&(i%m)==0){gbe(c,xo,0);gln(c,xo,-0.01);gst(c);gfz(c,xo,0,0,-hi*1.5,n,'#00a050','center')}if(c['slines']){gbe(c,xo,0);gln(c,xo,1);gst(c)}}
var xhr=x1-(x1%3600);
gss(c,'brown');
if(c['tkey']||c['tlines']){var hlv=c['hln'][c['hl']];hrs=c['hrs'][c['hr']]*3600/hlv;
var l=0;tpos=2.7;if(c['over']){tpos=1.5}
for(var i=xhr;i>=x0;i-=hrs){var n=dfmt(c,i);var xo=(i-x0)/(x1-x0);if(c['tkey']&&((l%hlv)==0)){gbe(c,xo,0);gln(c,xo,-0.02);gst(c);gfz(c,xo,0,0,-hi*tpos,n,'brown','center')}if(c['tlines']){gbe(c,xo,0);gln(c,xo,1);gst(c)}l++}}
glw(c,1);
gss(c,'#0000c0');
if(c['smooth']){var xa=0,ya=0,xb=0,yb=0;
for(var i=0;i<xn;i++){var x=ar[vx+i];var y=ar[vy+i];var xo=(x-x0)/(x1-x0);var yo=(y-y0)/(y1-y0);if(f==1){gbe(c,xo,yo);f=0;xb=xo;yb=yo}else{gct(c,(xa+xb)/2,(ya+yb)/2,xb,yb,(xb+xo)/2,(yb+yo)/2)}xa=xb;ya=yb;xb=xo;yb=yo}gct(c,(xa+xb)/2,(ya+yb)/2,xo,yo,xo,yo);gst(c);}
else{for(var i=0;i<xn;i++){var x=ar[vx+i];var y=ar[vy+i];var xo=(x-x0)/(x1-x0);var yo=(y-y0)/(y1-y0);if(f==1){gbe(c,xo,yo);f=0}else{gln(c,xo,yo)}}gst(c);}
glw(c,1);
gss(c,'red');
var y=(av-y0)/(y1-y0);
gbe(c,0,y);gln(c,1,y);gst(c);
var t=''+av.toFixed(2)+'av';gfz(c,1,y,1,0,t,'red','left')
if(c['tkey']){var col,hrl=c['hrs'].length;for(var i=0;i<hrl;i++){if(c['hr']==i){col='red'}else{col='black'}gfz(c,1,0,c['xo']-c['pxe'],hi*(i+1)*2,''+c['hrs'][i],col,'end')}for(var i=0;i<c['hln'].length;i++){if(c['hl']==i){col='red'}else{col='black'}gfz(c,1,0,c['xo']-c['pxe'],hi*(i+2+hrl)*2,''+c['hrs'][i],col,'end')}}
}
function sn(i,shi){if(shi.indexOf(' Shift ')<0){return ''+(i%10)}else{return shi.replace(/.* ([a-z])[a-z]*$/,'$1')}}
function gc(c){var div=document.getElementById('can0');while(div.firstChild){div.removeChild(div.firstChild)}c['can']=document.createElement('canvas');c['can'].id='can';c['wx']=window.innerWidth;c['wy']=window.innerHeight;c['xm']=Math.round(c['wx']*0.9+0.5);c['ym']=Math.round(c['wy']*0.8+0.5);if(c['ym']>c['xm']){c['ym']=c['xm']}c['xo']=0.0;c['yo']=0.0;c['ctx']=c['can'].getContext('2d');c['ctx'].canvas.width=c['xm']+1;c['ctx'].canvas.height=c['ym']+1;div.appendChild(c['can']);c['pxe']=Math.max(Math.round(c['xm']/250),1)}
function opts(t,i){var e=document.getElementById(i);if(t.checked){e.style.visibility='visible'}else{e.style.visibility='hidden'}}
function ghrs(c){c['hrs']=[1,2,3,4,6,8,12,24];c['hln']=[1,2,3,4,6]}
function gopt(c,cbx){for(var i=0;i<cbx.length;i++){ccb(c,cbx[i])}c['hr']=4;c['hl']=0}
function doinit(cbx,xon){for(var i=0;i<cbx.length;i++){var e=document.getElementById(cbx[i]);if(e){var n=gcn(cbx[i]);if(n==''){if(xon[cbx[i]]){e.checked=true}else{e.checked=false}}else{if(n=='1'){e.checked=true}else{e.checked=false}}}}}
";
 addScript($g);
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
	$page_scripts .= "</script>";

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
