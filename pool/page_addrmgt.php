<?php
#
function addrmgtuser($data, $user, $err)
{
 $pg = '<h1>Address Management</h1>';

 if ($err != '')
	$pg .= "<span class=err>$err<br><br></span>";

 $pg .= makeForm('addrmgt');
 $pg .= "<table callpadding=0 cellspacing=0 border=0>\n";
 $pg .= '<tr class=title>';
 $pg .= '<td class=dl>Address</td>';
 $pg .= '<td class=dr>Ratio</td>';
 $pg .= '<td class=dr>%</td>';
 $pg .= '</tr>';

 # new row template for '+'
 $pg .= '<tr class=hid id=bs>';
 $pg .= '<td class=dl>';
 $pg .= "<input type=text size=42 name='addr:' value=''>";
 $pg .= '</td>';
 $pg .= '<td class=dr>';
 $pg .= "<input type=text size=6 name='ratio:' value='0' id=rat onchange='repc()'>";
 $pg .= '</td>';
 $pg .= '<td class=dr>';
 $pg .= "<span id=per>0.00%</span>";
 $pg .= '</td>';
 $pg .= "</tr>\n";

 $ans = userSettings($user);

 $offset = 0;
 $count = 0;
 if ($ans['STATUS'] == 'ok')
 {
	$count = $ans['rows'];
	for ($i = 0; $i < $count; $i++)
	{
		if ((($offset) % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$addr = $ans['addr:'.$i];
		$pg .= '<td class=dl>';
		$pg .= "<input type=text size=42 name='addr:$i' value='$addr'>";
		$pg .= '</td>';
		$ratio = intval($ans['ratio:'.$i]);
		$pg .= '<td class=dr>';
		$pg .= "<input type=text size=6 name='ratio:$i' value='$ratio' id=rat$i onchange='repc()'>";
		$pg .= '</td>';
		$pg .= '<td class=dr>';
		$pg .= "<span id=per$i>%</span>";
		$pg .= '</td>';
		$pg .= "</tr>\n";

		$offset++;
	}
	if ((($offset++) % 2) == 0)
		$row = 'even';
	else
		$row = 'odd';
	$pg .= "<tr class=$row id=plus>";
	$pg .= '<td colspan=3 class=dl>';
	$pg .= "<input type=button value='+' onclick='return adrw();'>";
	$pg .= '</td></tr>';

	if ((($offset++) % 2) == 0)
		$row = 'even';
	else
		$row = 'odd';
	$pg .= "<tr class=$row>";
	$pg .= '<td colspan=3 class=dc>';
	$pg .= 'Password: <input type=password name=pass size=20>';
	$pg .= '&nbsp;<input type=submit name=OK value=Save></td></tr>';
 }
 $pg .= '<tr><td colspan=3 class=dc><font size=-1><span class=st1>*</span>';
 $pg .= ' You must enter your password to save changes<br>';
 $pg .= 'A ratio of 0, will remove the address from the payouts</font></td></tr>';
 $pg .= "</table><input type=hidden name=rows value=$count id=rows></form>\n";

 $pg .= "<script type='text/javascript'>\n";
 $pg .= "function adrw(){var p=document.getElementById('plus');";
 $pg .=  "var r=document.getElementById('rows');var c=parseInt(r.value);";
 $pg .=  "var bs=document.getElementById('bs');var n=bs.cloneNode(true);n.id='z';";
 $pg .=  "n.className='odd';var ia=n.childNodes[0].firstChild;ia.name='addr:'+c;ia.value='';";
 $pg .=  "var ir=n.childNodes[1].firstChild;ir.id='rat'+c;ir.name='ratio:'+c;ir.value='0';";
 $pg .=  "var ip=n.childNodes[2].firstChild;ip.id='per'+c;ip.innerHTML='0.00%';";
 $pg .=  "p.parentNode.insertBefore(n, p);";
 $pg .=  "c++;r.value=c;return true}\n";
 $pg .= "function repc(){var c=parseInt(document.getElementById('rows').value);";
 $pg .=  "if(!isNaN(c)&&c>0&&c<1000){var v=[],tot=0;for(i=0;i<c;i++){";
 $pg .=  "var o=document.getElementById('rat'+i);var ov=parseInt(o.value);if(!isNaN(ov)&&ov>0)";
 $pg .=  "{tot+=ov;v[i]=ov}else{o.value='0';v[i]=0}";
 $pg .=  "}for(i=0;i<c;i++){var p;var r=document.getElementById('per'+i);if(tot<=0)";
 $pg .=  "{p=0}else{p=v[i]*100/tot};r.innerHTML=p.toFixed(2)+'%';";
 $pg .=  "}}};\nrepc();</script>";

 return $pg;
}
#
function doaddrmgt($data, $user)
{
 $err = '';
 $OK = getparam('OK', false);
 $count = getparam('rows', false);
 $pass = getparam('pass', false);
 if ($OK == 'Save' && !nuem($count) && !nuem($pass))
 {
	if ($count > 0 && $count < 1000)
	{
		$addrarr = array();
		for ($i = 0; $i < $count; $i++)
		{
			$addr = getparam('addr:'.$i, false);
			$ratio = getparam('ratio:'.$i, false);
			if (!nuem($addr) && !nuem($ratio))
				$addrarr[] = array('addr' => $addr, 'ratio' => $ratio);
		}
		$ans = userSettings($user, null, $addrarr, $pass);
		if ($ans['STATUS'] != 'ok')
			$err = $ans['ERROR'];
	}
 }

 $pg = addrmgtuser($data, $user, $err);

 return $pg;
}
#
function show_addrmgt($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'doaddrmgt', $page, $menu, $name, $user);
}
#
?>
