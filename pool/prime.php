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
 else
 {
	if (isset($menu['Admin']))
		unset($menu['Admin']);
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
		'gap'  => NULL,
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
		'Workers' => 'workers',
		'Payments' => 'payments',
		'Settings' => 'settings'
	),
	'Pool' => array(
		'Stats' => 'stats',
		'Blocks' => 'blocks'
	),
	'Admin' => NULL,
	'gap' => NULL,
	'Help' => array(
		'Help' => 'help',
		'Payouts' => 'payout'
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
