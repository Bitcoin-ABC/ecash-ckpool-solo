<?php
#
include_once('email.php');
#
function addrmgtuser($data, $user, $err)
{
 $pg = '<h1>Address Management</h1>';

 if ($err != '')
	$pg .= "<span class=err>$err<br><br></span>";

 $pg .= makeForm('addrmgt');
 $pg .= "<table cellpadding=0 cellspacing=0 border=0>\n";
 $pg .= '<thead><tr class=title>';
 $pg .= '<td class=dc>#</td>';
 $pg .= '<td class=dl>Address</td>';
 $pg .= '<td class=dl>ID</td>';
 $pg .= '<td class=dr>Ratio</td>';
 $pg .= '<td class=dr>%</td>';
 $pg .= '</tr></thead>';

 # new row template for '+'
 $pg .= '<tr class=hid id=bs>';
 $pg .= '<td class=dc> </td>';
 $pg .= '<td class=dl>';
 $pg .= "<input type=text size=36 name='addr:' value=''>";
 $pg .= '</td>';
 $pg .= '<td class=dl>';
 $pg .= "<input type=text size=16 name='payname:' value=''>";
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
	$pg .= '<tbody>';
	if (isset($ans['limit']))
		$limit = $ans['limit'];
	else
		$limit = 1;
	$count = $ans['rows'];
	# this will output any DB rows > limit but DB update will ignore extras
	for ($i = 0; $i < $count; $i++)
	{
		if ((($offset) % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$addr = $ans['addr:'.$i];
		$pg .= '<td class=dc>'.($i+1).'</td>';
		$pg .= '<td class=dl>';
		$pg .= "<input type=text size=36 name='addr:$i' value='$addr'>";
		$pg .= '</td>';
		$nam = htmlspecialchars($ans['payname:'.$i]);
		$pg .= '<td class=dl>';
		$pg .= "<input type=text size=16 name='payname:$i' value='$nam'>";
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
	if ($offset < $limit) {
		if ((($offset++) % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';
		$pg .= "<tr class=$row id=plus><td class=dc>";
		$pg .= "<input type=button value='+' onclick='return adrw($limit);'>";
		$pg .= "</td><td colspan=4 class=dl><font size=-1>limit $limit</font></td></tr>";
	}

	$pg .= '</tbody><tfoot>';
	if ((($offset++) % 2) == 0)
		$row = 'even';
	else
		$row = 'odd';
	$pg .= "<tr class=$row>";
	$pg .= '<td class=dr>&nbsp;</td>';
	$pg .= '<td class=dr>Password:</td>';
	$pg .= '<td class=dl><input type=password name=pass size=20></td>';
	$pg .= '<td colspan=2>&nbsp;</td></tr>';

	if ((($offset++) % 2) == 0)
		$row = 'even';
	else
		$row = 'odd';
	$pg .= "<tr class=$row>";
	$pg .= '<td class=dr>&nbsp;</td>';
	$pg .= '<td class=dr><span class=st1>*</span>2nd Authentication:</td>';
	$pg .= '<td class=dl><input name=2fa size=10>';
	$pg .= ' <input type=submit name=OK value=Save></td>';
	$pg .= '<td colspan=3 class=dl>&nbsp;</td></tr>';

	$pg .= '<tr><td colspan=5 class=dc><font size=-1>';
	$pg .= "<span class=st1>*</span>Leave blank if you haven't enabled it<br>";
	$pg .= 'You must enter your password to save changes<br>';
	$pg .= 'A ratio of 0, will remove the address from the payouts</td></tr></tfoot>';
 }
 $pg .= "</table><input type=hidden name=rows value=$count id=rows></form>\n";

 # TODO - adrw() update the odd/even class for the new row and rows below it
 # TODO - move the js functions into inc.php
 $pg .= "<script type='text/javascript'>\n";
 $pg .= "function adrw(l){var p=document.getElementById('plus');";
 $pg .=  "var r=document.getElementById('rows');var c=parseInt(r.value);";
 $pg .=  "var bs=document.getElementById('bs');var n=bs.cloneNode(true);n.id='z';";
 $pg .=  "var ia=n.childNodes[1].firstChild;ia.name='addr:'+c;ia.value='';";
 $pg .=  "var ipn=n.childNodes[2].firstChild;ipn.name='payname:'+c;ipn.value='';";
 $pg .=  "var ir=n.childNodes[3].firstChild;ir.id='rat'+c;ir.name='ratio:'+c;ir.value='0';";
 $pg .=  "var ip=n.childNodes[4].firstChild;ip.id='per'+c;ip.innerHTML='0.00%';";
 $pg .=  "p.parentNode.insertBefore(n, p);";
 $pg .=  "c++;r.value=c;if(c>=l){p.parentNode.removeChild(p)}";
 $pg .=  "n.childNodes[0].innerHTML=''+c;n.className='odd';return true}\n";
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
 $twofa = getparam('2fa', false);
 $mfail = false;
 if ($OK == 'Save' && !nuem($count) && !nuem($pass))
 {
	if ($count > 0 && $count < 1000)
	{
		$mfail = true;
		$addrarr = array();
		for ($i = 0; $i < $count; $i++)
		{
			$addr = getparam('addr:'.$i, false);
			$nam = getparam('payname:'.$i, false);
			if (nuem($nam))
				$nam = '';
			$ratio = getparam('ratio:'.$i, false);
			if (!nuem($addr) && !nuem($ratio))
				$addrarr[] = array('addr' => trim($addr), 'payname' => trim($nam), 'ratio' => $ratio);
		}
		$ans = userSettings($user, null, $addrarr, $pass, $twofa);
		if ($ans['STATUS'] != 'ok')
			$err = $ans['ERROR'];
		else
		{
			$ans = userSettings($user);
			if ($ans['STATUS'] != 'ok')
				goto meh;
			if (isset($ans['email']))
				$email = $ans['email'];
			else
				goto meh;

			$emailinfo = getOpts($user, emailOptList());
			if ($emailinfo['STATUS'] != 'ok')
				goto meh;
			else
				payoutAddressChanged($email, zeip(), $emailinfo);
		}
		$mfail = false;
	}
 }
meh:
 if ($mfail == true)
 {
	if ($err != '')
		$err .= '<br>';
	$err .= 'An error occurred, check your details below';
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
