<?php
#
function uspg($nc)
{
$g = "function gdrw(c,d,cbx){gc(c);ghrs(c);gopt(c,cbx);
gfs(c,'white');gss(c,'#0000c0');glw(c,2);gbd(c);
var rows=d['rows'],ymin=-1,ymax=0,xmin=-1,xmax=0,tda=[];
var w=d['arp'].split(',');var cols=d['cols'].split(',');
gsh(c,w);
for(var j=1;j<w.length;j++){tda[j-1]=0}
for(var i=0;i<rows;i++){var s=parseFloat(d['start:'+i]);var e=parseFloat(d['end:'+i]);d['nx:'+i]=sn(i,d['shift:'+i]);if(xmin==-1||xmin>s){xmin=s}if(xmax<e){xmax=e}d['vx:'+i]=(s+e)/2.0;
for(var j=1;j<w.length;j++){var pre=w[j];var ths=0,nam=pre+'diffacc:'+i;if(d[nam]){var da=parseFloat(d[nam]);ths=(da/(e-s))*Math.pow(2,32)/Math.pow(10,12);tda[j-1]+=da}d[pre+'ths:'+i]=ths;if(ymin==-1||ymin>ths){ymin=ths}if(ths>ymax)ymax=ths;document.getElementById('worker'+j).value=d[pre+'worker']}
}
for(var j=1;j<w.length;j++){tda[j-1]*=(Math.pow(2,32)/Math.pow(10,12)/(xmax-xmin))}
var p5=(ymax-ymin)*0.05;ymax+=p5;ymin-=p5;if(ymin<0){ymin=0}
if(c['zerob']){ymin=0}
ghg(c,xmax-xmin);
ggr(c,0.9,0.9,'TH/s',rows,xmin,xmax,ymin,ymax,d,'nx:','vx:','ths:',tda,w,cols)}
c={};
function dodrw(data,cbx){if(hasCan()){gdrw(c,sep(data),cbx)}}
function gact(t){if(t.checked){scnv(t.id,1)}else{scnv(t.id,0)}godrw(0)}
function wch(){var w='';for(var i=1;i<=$nc;i++){var e=document.getElementById('worker'+i);if(e&&e.value&&e.value.trim()){if(i>1){w+=','}w+=e.value.trim()}}if(w){scnv('workers',w)}}";
return $g;
}
#
function dousperf($data, $user)
{
 global $fld_sep, $val_sep;

 // This also defines how many worker fields there are
 $cols = array('#0000c0', '#00dd00', '#e06020', '#b020e0');
 $nc = count($cols);

 $workers = 'all';
 if (isset($_COOKIE['workers']))
 {
	$w = substr(trim($_COOKIE['workers']), 0, 1024);
	if ($w !== false)
	{
		$wa = explode(',', $w,  $nc+1);
		if (count($wa) > $nc)
		{
			$w = '';
			for ($i = 0; $i < $nc; $i++)
				$w .= (($i == 0) ? '' : ',').$wa[$i];
		}
		$workers = $w;
	}
 }

 $ans = getShiftData($user, $workers);

 $iCrap = strpos($_SERVER['HTTP_USER_AGENT'],'iP');
 if ($iCrap)
	$vlines = false;
 else
	$vlines = true;

 $pg = '<h1>User Shift Reward Performance</h1><br>';

 if ($ans['STATUS'] == 'ok' and $ans['DATA'] != '')
 {
	addGBase();
	addTips();
	$cbx = array('skey' => 'shift key', 'slines' => 'shift lines',
			'tkey' => 'time key', 'tlines' => 'time lines',
			'over' => 'key overlap', 'smooth' => 'smooth',
			'zerob' => 'zero based', 'utc' => 'utc');
	$xon = array('skey' => 1, 'utc' => 1);
	if ($vlines === true)
		$xon['slines'] = 1;

	$pg .= '<form>';

	$tt = "<ul class=tip><li>all = all workers</li><li>noname = worker with no workername</li>";
	$tt .= "<li>or full workername without the username i.e. .worker or _worker</li>";
	$tt .= "<li>add a '*' on the end to match multiple workers e.g. .S3*</li></ul>";
	$pg .= "<span class=q onclick='tip(\"wtip\",6000)'>?</span>";
	$pg .= "<span class=tip0><span class=notip id=wtip>$tt</span></span>";

	$i = 0;
	$datacols = '';
	$onch = " onchange='wch()'";
	foreach ($cols as $col)
	{
		$i++;
		$pg .= " <span class=nb><font color=$col>Worker$i";
		$pg .= "<input type=checkbox id=lin$i checked onclick='godrw(0)'>:</font>";
		$pg .= "<input type=text size=10 id=worker$i$onch> </span>";

		if ($i > 1)
			$datacols .= ',';
		$datacols .= $col;
	}

	$oncl = "wch();location.href=\"".makeURL('usperf')."\"";
	$pg .= "<button type=button onclick='$oncl'>Update</button></form><div>";
	foreach ($cbx as $nam => $txt)
	{
		$pg .= ' <span class=nb>';
		$pg .= "<input type=checkbox id=$nam onclick='gact(this)'>";
		$pg .= "$txt&nbsp;</span>";
	}

	$pg .= '</div>';
	$pg .= '<div id=can0><canvas id=can width=1 height=1>';
	$pg .= 'A graph will show here if your browser supports html5/canvas';
	$pg .= "</canvas></div>\n";
	$data = str_replace(array("\\","'"), array("\\\\","\\'"), $ans['DATA']);
	$data .= $fld_sep . 'cols' . $val_sep . $datacols;
	$pg .= "<script type='text/javascript'>\n";
	$pg .= uspg($nc);
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
