<?php
#
function nutem($str)
{
 if (($str === null) or trim($str) == '')
	return true;
 else
	return false;
}
#
function nuem($str)
{
 if (($str === null) or $str == '')
	return true;
 else
	return false;
}
#
function getparam($name, $both)
{
 $a = null;
 if (isset($_POST[$name]))
	$a = $_POST[$name];

 if (($both === true) and ($a === null))
 {
	if (isset($_GET[$name]))
		$a = $_GET[$name];
 }

 if ($a == '' || $a == null)
	return null;

 // limit to 1K just to be sure
 return substr($a, 0, 1024);
}
#
?>
