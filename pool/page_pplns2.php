<?php
#
function stnum($num)
{
 $b4 = '';
 $af = '';
 $fmt = number_format($num, 0);
 if ($num > 99999999)
	$b4 = '<span class=urg>';
 else if ($num > 9999999)
	$b4 = '<span class=warn>';
 if ($b4 != '')
	$af = '</span>';
 return $b4.$fmt.$af;
}
#
# ... Of course ... check the output and add the txin ... etc.
function calctx($ans, $count, $miner_sat, $diffacc_total)
{
 $pg = '<br><table cellpadding=0 cellspacing=0 border=0>';
 $pg .= '<tr><td>';

 $dust = getparam('dust', true);
 if (nuem($dust) || $dust <= 0)
	$dust = 10000;

 $fee = getparam('fee', true);
 if (nuem($fee) || $fee < 0)
	$fee = 0;
 $fee *= 100000000;

 $adr = array();
 $ers = '';
 $unpaid = 0;
 $change = $miner_sat;
 $dust_amt = 0; # not included in $change
 for ($i = 0; $i < $count; $i++)
 {
	$username = $ans['user:'.$i];
	$diffacc_user = $ans['diffacc:'.$i];
	$pay_sat = $ans['amount:'.$i];
	$payaddress = $ans['payaddress:'.$i];
	if ($payaddress == 'hold')
	{
		$dd = '';
		if ($pay_sat > 0 && $pay_sat < $dust)
			$dd = ' (dust)';
		$ers .= "Hold for '$username'$dd ($pay_sat)<br>";
		$unpaid += $pay_sat;
		continue;
	}
	if ($payaddress == 'none')
	{
		$parts = explode('.', $username);
		if (btcaddr($parts[0]) === true)
			$payaddress = $parts[0];
		else
		{
			if ($pay_sat > 0)
			{
				$dd = '';
				if ($pay_sat < $dust)
					$dd = ' (dust)';
				$ers .= "No address for '$username'$dd ($pay_sat)<br>";
			}
			$unpaid += $pay_sat;
			continue;
		}
	}
	if (isset($adr[$payaddress]))
		$adr[$payaddress] += $pay_sat;
	else
		$adr[$payaddress] = $pay_sat;

	$change -= $pay_sat;
 }

 $txout = '';
 $comma = '';
 foreach ($adr as $payaddress => $pay_sat)
 {
	if ($pay_sat < $dust)
		$dust_amt += $pay_sat;
	else
	{
		$txout .= "$comma\"$payaddress\":".btcfmt($pay_sat);
		$comma = ', ';
	}
 }

 if ($change > 0 || $dust_amt > 0 || $change < $fee)
 {
	$pg .= "<span class=err>Dust limit = $dust = ".btcfmt($dust);
	$pg .= ", Dust amount = $dust_amt = ".btcfmt($dust_amt);
	$pg .= ",<br>Upaid = $unpaid = ".btcfmt($unpaid);
	$pg .= ", Change = $change = ".btcfmt($change);
	$pg .= ",<br>Fee = $fee = ".btcfmt($fee)."</span><br>";

	if ($change < $fee)
		$ers .= "Change ($change) is less than Fee ($fee)<br>";

	if (($dust_amt + $change - $fee) > 0)
	{
		$txout .= "$comma\"&lt;changeaddress&gt;\":";
		$txout .= btcfmt($dust_amt + $change - $fee);
		$comma = ', ';
	}
 }

 if (strlen($ers) > 0)
	$pg .= "<span class=err>$ers</span><br>";

 $txn = '[{"txid":"&lt;txid1&gt;","vout":&lt;n&gt;},';
 $txn .= '{"txid":"&lt;txid2&gt;","vout":&lt;n&gt;}] ';
 $txn .= '{'.$txout.'}<br>';

 $pg .= $txn.'</td></tr></table>';
 return $pg;
}
#
function fmtdata($code, $val)
{
 switch ($code)
 {
 case ',':
	$ret = number_format($val);
	break;
 case '.':
	$ret = number_format($val, 1);
	break;
 case '@':
	$ret = howmanyhrs($val, true);
	break;
 default:
	$ret = $val;
 }
 return $ret;
}
#
function dopplns2($data, $user)
{
 global $send_sep;

 $pg = '<h1>CKPool</h1>';

 $blk = getparam('blk', true);
 if (nuem($blk))
 {
	$tx = '';
	# so can make a link
	$blkuse = getparam('blkuse', true);
	if (nuem($blkuse))
		$blkuse = '';
	else
		$tx = 'y';
	$pg = '<br>'.makeForm('pplns2')."
Block: <input type=text name=blk size=10 value='$blkuse'>
&nbsp; Tx: <input type=text name=tx size=1 value='$tx'>
&nbsp; Dust (Satoshi): <input type=text name=dust size=5 value='10000'>
&nbsp; Fee (BTC): <input type=text name=fee size=5 value='0.0'>
&nbsp;<input type=submit name=Calc value=Calc>
</form>";
 }
 else
 {
	$tx = getparam('tx', true);
	if (nuem($tx) || substr($tx, 0, 1) != 'y')
		$dotx = false;
	else
		$dotx = true;

	$flds = array('height' => $blk);
	$msg = msgEncode('pplns2', 'pplns2', $flds, $user);
	$rep = sendsockreply('pplns2', $msg, 4);
	if ($rep == false)
		$ans = array();
	else
		$ans = repDecode($rep);


	if ($ans['ERROR'] != null)
		return '<font color=red size=+1><br>'.$ans['STATUS'].': '.$ans['ERROR'].'</font>';

	if (!isset($ans['pplns_last']))
		return '<font color=red size=+1><br>Partial data returned</font>';

	$reward_sat = $ans['block_reward'];
	$miner_sat = $ans['miner_reward'];
	$ans['miner_sat'] = $miner_sat;

	$data = array(	'Block' => 'block',
			'Block Status' => 'block_status',
			'Block Hash' => 'block_hash',
			'Block Reward (Satoshis)' => 'block_reward',
			'Miner Reward (Satoshis)' => 'miner_sat',
			'PPLNS Wanted' => '.diff_want',
			'PPLNS Used' => '.diffacc_total',
			'Elapsed Seconds' => ',pplns_elapsed',
			'Elapsed Time' => '@pplns_elapsed',
			'Users' => 'rows',
			'Oldest Workinfoid' => 'begin_workinfoid',
			'Oldest Time' => 'begin_stamp',
			'Oldest Epoch' => 'begin_epoch',
			'Block Workinfoid' => 'block_workinfoid',
			'Block Time' => 'block_stamp',
			'Block Epoch' => 'block_epoch',
			'Newest Workinfoid' => 'end_workinfoid',
			'Newest Share Time' => 'end_stamp',
			'Newest Share Epoch' => 'end_epoch',
			'Network Difficulty' => 'block_ndiff',
			'PPLNS Factor' => 'diff_times',
			'PPLNS Added' => 'diff_add',
			'Accepted Share Count' => ',acc_share_count',
			'Total Share Count' => ',total_share_count',
			'ShareSummary Count' => ',ss_count',
			'WorkMarkers Count' => ',wm_count',
			'MarkerSummary Count' => ',ms_count');

	$pg = '<br><a href=https://blockchain.info/block-height/';
	$pg .= $ans['block'].'>Blockchain '.$ans['block']."</a><br>\n";

	if (strlen($ans['marks_status']) > 0)
	{
		$pg .= '<br><span class=err>';
		$msg = $ans['marks_status'];
		$pg .= str_replace(' ', '&nbsp;', $msg)."</span><br>\n";
	}

	if (strlen($ans['block_extra']) > 0)
	{
		$pg .= '<br><span class=err>';
		$msg = $ans['block_status'].' - '.$ans['block_extra'];
		$pg .= str_replace(' ', '&nbsp;', $msg)."</span><br>\n";
	}

	$pg .= "<br><table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= '<tr class=title>';
	$pg .= '<td class=dl>Name</td>';
	$pg .= '<td class=dr>Value</td>';
	$pg .= "</tr>\n";
	$i = 0;
	foreach ($data as $dsp => $name)
	{
		if (($i++ % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= "<td class=dl>$dsp</td>";
		switch ($name[0])
		{
			case ',':
			case '.':
			case '@':
				$nm = substr($name, 1);
				$fmt = fmtdata($name[0], $ans[$nm]);
				break;
			default:
				$fmt = $ans[$name];
				break;
		}
		if ($dsp == 'Elapsed Seconds')
		{
			$pl = $ans['diffacc_total'] * pow(2,32) / $ans['pplns_elapsed'];
			$fmt .= ' ' . dsprate($pl);
		}
		$pg .= "<td class=dr>$fmt</td>";
		$pg .= "</tr>\n";
	}

	$pg .= "</table><br><table cellpadding=0 cellspacing=0 border=0>\n";
	$pg .= '<tr class=title>';
	$pg .= '<td class=dl>User</td>';
	$pg .= '<td class=dr>Diff Accepted</td>';
	$pg .= '<td class=dr>%</td>';
	$pg .= '<td class=dr>Avg Hashrate</td>';
	$pg .= '<td class=dr>BTC -0.9%</td>';
	$pg .= '<td class=dr>Address</td>';
	$pg .= "</tr>\n";

	$diffacc_total = $ans['diffacc_total'];
	if ($diffacc_total == 0)
		$diffacc_total = pow(10,15);
	$elapsed = $ans['pplns_elapsed'];
	$count = $ans['rows'];
	$tot_pay = 0;
	for ($i = 0; $i < $count; $i++)
	{
		$diffacc_user = $ans['diffacc:'.$i];
		$diffacc_percent = number_format(100.0 * $diffacc_user / $diffacc_total, 3).'%';
		$avg_hash = number_format($diffacc_user / $elapsed * pow(2,32), 0);
		$pay_sat = $ans['amount:'.$i];
		$payaddress = $ans['payaddress:'.$i];

		if (($i % 2) == 0)
			$row = 'even';
		else
			$row = 'odd';

		$pg .= "<tr class=$row>";
		$pg .= '<td class=dl>'.$ans['user:'.$i].'</td>';
		$pg .= "<td class=dr>$diffacc_user</td>";
		$pg .= "<td class=dr>$diffacc_percent</td>";
		$pg .= "<td class=dr>$avg_hash</td>";
		$pg .= '<td class=dr>'.btcfmt($pay_sat).'</td>';
		$pg .= "<td class=dr>$payaddress</td>";
		$pg .= "</tr>\n";

		$tot_pay += $pay_sat;
	}
	if (($i % 2) == 0)
		$row = 'even';
	else
		$row = 'odd';

	$pg .= "<tr class=$row>";
	$pg .= '<td class=dl colspan=3></td>';
	$pg .= '<td class=dr></td>';
	$pg .= '<td class=dr>'.btcfmt($tot_pay).'</td>';
	$pg .= '<td class=dr></td>';
	$pg .= "</tr>\n";
	$pg .= "</table>\n";

	if ($dotx === true)
		$pg .= calctx($ans, $count, $miner_sat, $diffacc_total);
 }

 return $pg;
}
#
function show_pplns2($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dopplns2', $page, $menu, $name, $user);
}
#
?>
