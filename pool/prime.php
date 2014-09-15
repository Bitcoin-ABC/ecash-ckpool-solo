<?php
#
global $stt;
$stt = microtime();
#
include_once('param.php');
include_once('base.php');
#
function process($p, $user)
{
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
 if ($user == 'Kano' || $user == 'ckolivas' || $user == 'wvr2' || $user == 'aphorise')
 {
	$menu['Admin']['ckp'] = 'ckp';
	$menu['Admin']['PPLNS'] = 'pplns';
	$menu['Admin']['AllWork'] = 'allwork';
 }
 else
	unset($menu['Admin']);
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
function check()
{
 tryLogInOut();
 $who = loggedIn();
 if ($who === false)
 {
	if (requestRegister() == true)
		showPage('reg', NULL, '', $who);
	else
		showIndex();
 }
 else
 {
	$p = getparam('k', true);
	process($p, $who);
 }
}
#
check();
#
?>
