<?php
#
global $stt;
$stt = microtime(true);
#
global $loginfailed;
$loginfailed = false;
#
include_once('param.php');
include_once('base.php');
#
function process($p, $user, $menu)
{
 $info = homeInfo($user);
 if (is_array($info) && isset($info['u_multiaddr']))
 {
	if (isset($menu['Account']))
		$menu['Account']['Addresses'] = 'addrmgt';
	if (isset($menu['Workers']))
		$menu['Workers']['Percents'] = 'percent';
 }
 if ($user == 'Kano' || $user == 'ckolivas')
 {
	$menu['Admin']['ckp'] = 'ckp';
	$menu['Admin']['PPLNS2'] = 'pplns2';
	$menu['Admin']['PPLNS'] = 'pplns';
	$menu['Admin']['AllWork'] = 'allwork';
	$menu['Admin']['IPS'] = 'ips';
	$menu['Admin']['Events'] = 'events';
 }
bp:
 $page = '';
 $n = '';
 foreach ($menu as $item => $options)
	if ($options !== NULL)
		foreach ($options as $name => $pagename)
			if ($pagename === $p)
			{
				$page = $p;
				$n = " - $name";
			}

 if ($page === '' and $p == 'blocks')
 {
	$p = 'pblocks';
	goto bp;
 }
 if ($page === '')
	showPage($info, 'index', $menu, '', $user);
 else
	showPage($info, $page, $menu, $n, $user);
}
#
function def_menu()
{
 $dmenu = array('Home'  => array('Home' => ''),
		'Pool' => array(
			'Blocks' => 'pblocks'
		),
		'gap' => array( # options not shown
				'API' => 'api'),
		'Help' => array(
				'Payouts' => 'payout'));
 return $dmenu;
}
#
function check()
{
 $dmenu = def_menu();
 $menu = array(
	'Home' => array(
		'Home' => ''
	),
	'Account' => array(
		'Rewards' => 'mpayouts',
		'Payments' => 'payments',
		'Settings' => 'settings',
		'User Settings' => 'userset',
		'2FA Settings' => '2fa'
	),
	'Workers' => array(
		'Shifts' => 'shifts',
		'Shift Graph' => 'usperf',
		'Workers' => 'workers',
		'Management' => 'workmgt'
	),
	'Pool' => array(
		'Stats' => 'stats',
		'Blocks' => 'blocks',
		'Graph' => 'psperf',
		'Acclaim' => 'userinfo',
		'Luck' => 'luck'
	),
	'Admin' => NULL,
	'gap' => array( # options not shown
			'API' => 'api',
			'PBlocks' => 'pblocks'
	),
	'Help' => array(
		'Payouts' => 'payout'
	)
 );
 tryLogInOut();
 $who = loggedIn();
 if ($who === false)
 {
	$p = getparam('k', true);
	if ($p == 'reset')
		showPage(NULL, 'reset', $dmenu, '', $who);
	else
	{
		if (requestLoginRegReset() == true)
			showPage(NULL, 'reg', $dmenu, '', $who);
		else
		{
			$p = getparam('k', true);
			process($p, $who, $dmenu);
		}
	}
 }
 else
 {
	$p = getparam('k', true);
	process($p, $who, $menu);
 }
}
#
check();
#
?>
