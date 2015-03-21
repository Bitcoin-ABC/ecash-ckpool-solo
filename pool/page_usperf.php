<?php
#
function uspg()
{
$g = "function gdrw(c,d,cbx){gc(c);ghrs(c);gopt(c,cbx);
gfs(c,'white');gss(c,'#0000c0');glw(c,2);gbd(c);
var rows=d['rows'],ymin=-1,ymax=0,xmin=-1,xmax=0,tda=0;
for(var i=0;i<rows;i++){var s=parseFloat(d['start:'+i]);var e=parseFloat(d['end:'+i]);var da=parseFloat(d['diffacc:'+i]);tda+=da;var ths=(da/(e-s))*Math.pow(2,32)/Math.pow(10,12);d['ths:'+i]=ths;if(ymin==-1||ymin>ths){ymin=ths}if(ths>ymax)ymax=ths;d['nx:'+i]=sn(i,d['shift:'+i]);if(xmin==-1||xmin>s){xmin=s}if(xmax<e){xmax=e}d['vx:'+i]=(s+e)/2.0};
var tav=(tda/(xmax-xmin))*Math.pow(2,32)/Math.pow(10,12);
var p5=(ymax-ymin)*0.05;ymax+=p5;ymin-=p5;if(ymin<0){ymin=0}
if(c['zerob']){ymin=0}
ggr(c,0.9,0.9,'TH/s',rows,xmin,xmax,ymin,ymax,d,'nx:','vx:','ths:',tav)}
c={};
function dodrw(data,cbx){if(hasCan()){gdrw(c,sep(data),cbx)}}
function gact(t){if(t.checked){scnv(t.id,1)}else{scnv(t.id,0)}godrw(0)}";
return $g;
}
#
function dousperf($data, $user)
{
 $ans = getShiftData($user);

 $iCrap = strpos($_SERVER['HTTP_USER_AGENT'],'iP');
 if ($iCrap)
	$vlines = false;
 else
	$vlines = true;

 $pg = '<h1>User Shift Reward Performance</h1><br>';
 if ($ans['STATUS'] == 'ok' and $ans['DATA'] != '')
 {
	addGBase();
	$cbx = array('skey' => 'shift key', 'slines' => 'shift lines',
			'tkey' => 'time key', 'tlines' => 'time lines',
			'over' => 'key overlap', 'smooth' => 'smooth',
			'zerob' => 'zero based', 'utc' => 'utc');
	$xon = array('skey' => 1, 'utc' => 1);
	if ($vlines === true)
		$xon['slines'] = 1;

	$pg .= '<div>';
	foreach ($cbx as $nam => $txt)
		$pg .= "&nbsp;<input type=checkbox id=$nam onclick='gact(this)'>$txt&nbsp;";

	$pg .= '</div>';
	$pg .= '<div id=can0><canvas id=can width=1 height=1>';
	$pg .= 'A graph will show here if your browser supports html5/canvas';
	$pg .= "</canvas></div>\n";
	$data = str_replace(array("\\","'"), array("\\\\","\\'"), $ans['DATA']);
	$pg .= "<script type='text/javascript'>\n";
	$pg .= uspg();
	$pg .= "\nfunction godrw(f){var cbx=[";
	$comma = '';
	foreach ($cbx as $nam => $txt)
	{
		$pg .= "$comma'$nam'";
		$comma = ',';
	}
	$pg .= '];if(f){var xon={};';
	foreach ($xon as $nam => $val)
		$pg .= "xon['$nam']=1;";
	$pg .= "doinit(cbx,xon)}dodrw('$data',cbx)};godrw(1);</script>\n";
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
