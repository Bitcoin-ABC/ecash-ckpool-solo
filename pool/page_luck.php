<?php
#
function lckg($nc, $av)
{
$g = "function gdrw(c,d,cbx){gc(c);ghrs(c);gopt(c,cbx);
gfs(c,'white');gss(c,'#0000c0');glw(c,2);gbd(c);
var rows=d['rows'],ymin=0,ymax=0,xmin=-1,xmax=0,tlk=[];
var w=d['arp'].split(',');var cols=d['cols'].split(',');
gsh(c,w);
for(var j=1;j<w.length;j++){tlk[j-1]=$av}
for(var i=0;i<rows;i++){var s=parseFloat(d['firstcreatedate:'+i]);d['vx:'+i]=s;if(xmin==-1||xmin>s){xmin=s}if(xmax<s){xmax=s}
for(var j=1;j<w.length;j++){var pre=w[j];var lk=0,nam=pre+'luck:'+i;if(d[nam]){lk=parseFloat(d[nam])}if(lk>ymax)ymax=lk}
}
if(ymax>500){ymax=500}
ghg(c,xmax-xmin);
ggr(c,0.90,0.90,'Luck%',rows,xmin,xmax,ymin,ymax,d,'seq:','vx:','luck:',tlk,w,cols)}
c={};
function dodrw(data,cbx){if(hasCan()){gdrw(c,sep(data),cbx)}}
function gact(t){if(t.checked){scnv(t.id,1)}else{scnv(t.id,0)}godrw(0)}";
return $g;
}
#
function doluck($data, $user)
{
 global $fld_sep, $val_sep;

 if ($user === null)
	$ans = getBlocks('Anon');
 else
	$ans = getBlocks($user);

 $pg = '<h1>Pool Avg Block Luck History</h1><br>';

 if ($ans['STATUS'] == 'ok' and isset($ans['rows']) and $ans['rows'] > 0)
 {
	$count = $ans['s_rows'] - 1;
	$av = number_format(100 * $ans['s_luck:'.$count], 3);

	for ($i = 0; $i < $count; $i++)
	// This also defines how many lines there are
	$cols = array('#0000c0', '#00dd00', '#e06020', '#b020e0');
	$nams = array(1, 5, 15, 25);
	$nc = count($cols);

	addGBase();
	$cbx = array('skey' => 'block key', 'slines' => 'block lines',
			'tkey' => 'time key', 'tlines' => 'time lines',
			'over' => 'key overlap', 'smooth' => 'smooth',
			'utc' => 'utc');
	$xon = array('skey' => 1, 'tkey' => 1, 'tlines' => 1, 'utc' => 1);

	$pg .= '<div>';
	foreach ($cbx as $nam => $txt)
	{
		$pg .= ' <span class=nb>';
		$pg .= "<input type=checkbox id=$nam onclick='gact(this)'>";
		$pg .= "$txt&nbsp;</span>";
	}
	$pg .= '</div><div>';

	$i = 1;
	$datacols = '';
	foreach ($cols as $col)
	{
		if ($i != 1)
			$pg .= '&nbsp;&nbsp;';
		if ($i == 2 || $i == 4)
			$chk = ' checked';
		else
			$chk = '';
		$pg .= "<span class=nb><font color=$col>";
		$pg .= "<input type=checkbox id=lin$i$chk onclick='godrw(0)'>: ";
		if ($nams[$i-1] == 1)
			$avs = '';
		else
			$avs = ' Avg';
		$pg .= $nams[$i-1]." Block Luck$avs</font></span>";

		if ($i > 1)
			$datacols .= ',';
		$datacols .= $col;
		$i++;
	}

	$pg .= '</div>';
	$pg .= '<div id=can0><canvas id=can width=1 height=1>';
	$pg .= 'A graph will show here if your browser supports html5/canvas';
	$pg .= "</canvas></div>\n";

	$count = $ans['rows'];
	# add the orphan/reject ratios to the subsequent blocks
	$dr = 0;
	for ($i = $count-1; $i >= 0; $i--)
	{
		$conf = $ans["confirmed:$i"];
		if ($conf == '1' or $conf == 'F')
		{
			$ans["diffratio:$i"] += $dr;
			$dr = 0;
		}
		else
			$dr += $ans["diffratio:$i"];
	}

	# $ans blocks are 0->rows-1 highest->lowest
	# build an array of valid block offsets (reversed lowest->highest)
	$off = array();
	for ($i = $count-1; $i >= 0; $i--)
	{
		$conf = $ans["confirmed:$i"];
		if ($conf == '1' or $conf == 'F')
			$off[] = $i;
	}

	$data = '';
	$count = count($off);
	$avg = 0;
	# each valid block offset number (lowest->highest)
	for ($j = 0; $j < $count; $j++)
	{
		$i = $off[$j];

		$data .= $fld_sep . "height:$j$val_sep";
		$data .= $ans["height:$i"];
		$data .= $fld_sep . "seq:$j$val_sep";
		$data .= $ans["seq:$i"];
		$data .= $fld_sep . "firstcreatedate:$j$val_sep";
		$data .= $ans["firstcreatedate:$i"];
		$data .= $fld_sep . "0_luck:$j$val_sep";
		$data .= number_format(100 * $ans['luck:'.$i], 3);

		$avg += $ans["diffratio:$i"];

		$l5c = $l15c = $l25c = 1;
		$l5 = $l15 = $l25 = $ans['diffratio:'.$i];

		# +/- offset from j (12 is the max for 25)
		for ($k = 1; $k <= 12; $k++)
		{
			# we want the (n-1)/2 on each side of the offset number
			foreach (array(-1, 1) as $s)
			{
				$o = $j + ($s * $k);
				if (0 <= $o && $o < $count)
				{
					$dr = $ans['diffratio:'.$off[$o]];
					if ($k <= 2) # (5-1)/2
					{
						$l5 += $dr;
						$l5c++;
					}
					if ($k < 7) # (15-1)/2
					{
						$l15 += $dr;
						$l15c++;
					}
					$l25 += $dr;
					$l25c++;
				}
			}
		}
		# luck is 1/(mean diffratio)
		$data .= $fld_sep . "1_luck:$j$val_sep";
		$data .= number_format(100 * $l5c / $l5, 3);
		$data .= $fld_sep . "2_luck:$j$val_sep";
		$data .= number_format(100 * $l15c / $l15, 3);
		$data .= $fld_sep . "3_luck:$j$val_sep";
		$data .= number_format(100 * $l25c / $l25, 3);
	}
	$data .= $fld_sep . 'rows' . $val_sep . $count;
	$data .= $fld_sep . 'arp' . $val_sep . ',0_,1_,2_,3_';
	$data .= $fld_sep . 'cols' . $val_sep . $datacols;

	$pg .= "<script type='text/javascript'>\n";
	$pg .= lckg($nc, 100*$count/$avg);
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
function show_luck($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doluck', $page, $menu, $name, $user);
}
#
?>
