<?php
#
function dopayout($data, $user)
{
 $N = 5;
 $t = "<span class=nn>$N</span>";
 $ot = "<span class=nn>1/$N</span>";
 $n = "<span class=nn>${N}Nd</span>";
 $n1 = '<span class=nn>N</span>';
 $n1d = '<span class=nn>Nd</span>';
 $bc = '+101 Confirms';
 $bm = 'Matured';
 $nd = 0;
 if (isset($data['info']['currndiff']))
  $nd = $data['info']['currndiff'];
 $nv = number_format($nd, 1);
 $nvx = number_format($N*$nd, 1);

 $pg = "<h1>Payouts</h1>
<table width=75% cellpadding=0 cellspacing=0 border=0><tr><td>

<span class=hdr>What payout method does the pool use?</span><br><br>
We use <b>PPL${n1}S</b> (<b>P</b>ay <b>P</b>er <b>L</b>ast $n1 <b>S</b>hares)<br><br>
<b>PPL${n1}S</b> means that when a block is found, the block reward is shared among the last $n1 shares that miners sent to the pool, up to when the block was found.<br>
The $n1 value the pool uses is $t times the network difficulty when the block is found - '$n'.<br><br>

<span class=hdr>How much of each block does the pool reward?</span><br><br>
Transaction fees are included in the miner reward.<br>
Pool fee is 0.9% of the total.<br><br>

<span class=hdr>How do the payments work?</span><br><br>
The $n means the pool rewards $t times the expected number of shares, each time a block is found.<br>
So each share will be paid appoximately $ot of it's expected value, in each block it gets a reward,<br>
but each share is also expected, on average, to be rewarded $t times in blocks found after the share is submitted to the pool.<br>
i.e. if pool luck was always 100% then each share is expected to be rewarded $t times.<br><br>
If pool luck is better than 100%, then the average share reward will be better than $t times.<br>
If pool luck is lower than 100%, then the average share reward will be less than $t times.<br><br>

<span class=hdr>What's a shift?</span></br><br>
When your miner sends shares to the pool, the shares are not stored individually, but rather summarised into shifts.<br>
Shifts are ~50min or less in length.<br>
Aproximately every 30s, the pool generates new work and sends that to all the miners.<br>
The pool also sends new work every time a block is found on the Bitcoin network.<br>
A shift summarises all the shares submitted to the pool for 100 work changes.<br>
However, when we find pool blocks, the current shift ends at the work in which the block was found<br>
and a new shift starts.<br>
A ckpool restart will also end the current shift and start a new shift.<br>
A network difficulty change will also end the current shift and start a new shift.<br><br>

<span class=hdr>So, what's the $n value?</span><br><br>
The current Bitcoin network value for $n1d is $nv and thus $n is <b>$nvx</b><br>
Bitcoin adjusts the $n1d value every 2016 blocks, which is about every 2 weeks.<br><br>
When a block is found, the reward process counts back shifts until the total share difficulty included is $n.<br>
Since shares are summarised into shifts, it will include the full shift at the end of the range counting backwards,<br>
so it usually will be a bit more than $n.<br><br>

<span class=hdr>When are payments sent out?</span><br><br>
The block 'Status' must first reach '$bc' on the Blocks page, and then is flagged as '$bm', before the reward is distributed.<br>
The block reward is sent out manually soon after that.<br><br>

</td></tr></table>";
 return $pg;
}
#
function show_payout($info, $page, $menu, $name, $user)
{
 gopage($info, NULL, 'dopayout', $page, $menu, $name, $user);
}
#
?>
