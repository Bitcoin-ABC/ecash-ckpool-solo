<?php
usleep(100000);
include_once('param.php');
?>
<!DOCTYPE html>
<html><head><title>CKPool</title><meta content='text/html; charset=iso-8859-1' http-equiv='Content-Type'></head><body>
<?php
function go()
{
 $a = getparam('a', true);
 if (substr($a, 0, 1) != '1')
	return;
 if (strlen($a) < 24)
	return;
 if (preg_match('/^[a-zA-Z0-9]*$/', $a) === false)
	return;
 $sta = "../pool/users/$a";
 if (file_exists($sta))
	echo file_get_contents($sta);
}
go();
?>
</body></html>
