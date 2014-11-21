<?php
#
global $stt;
$stt = microtime();
#
include_once('param.php');
include_once('base.php');
#
function process($p, $user, $menu)
{
 if ($user == 'Kano' || $user == 'ckolivas' || $user == 'wvr2' || $user == 'aphorise')
 {
	$menu['Admin']['ckp'] = 'ckp';
	$menu['Admin']['PPLNS'] = 'pplns';
	$menu['Admin']['AllWork'] = 'allwork';
 }
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

 if ($page === '')
	showPage('index', $menu, '', $user);
 else
	showPage($page, $menu, $n, $user);
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
		'Help' => array('Help' => 'help',
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
		'Payments' => 'payments',
		'Settings' => 'settings',
		'User Settings' => 'userset'
	),
	'Workers' => array(
		'Workers ' => 'workers',
		'Management' => 'workmgt',
	),
	'Pool' => array(
		'Stats' => 'stats',
		'Blocks' => 'blocks'
	),
	'Admin' => NULL,
	'gap' => array( # options not shown
			'API' => 'api'
	),
	'Help' => array(
		'Payouts' => 'payout',
		'Workers ' => 'workers',
		'Blocks' => 'blocks'
	)
 );
 tryLogInOut();
 $who = loggedIn();
 if ($who === false)
 {
	$p = getparam('k', true);
	if ($p == 'reset')
		showPage('reset', $dmenu, '', $who);
	else
	{
		if (requestRegister() == true)
			showPage('reg', $dmenu, '', $who);
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
