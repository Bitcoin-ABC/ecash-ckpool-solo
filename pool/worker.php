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
 $f = substr($a, 0, 1);
 if ($f != '1' and $f != '3')
	return;
 if (preg_match('/^[a-zA-Z0-9]{24,}[\._]?[a-zA-Z0-9\._]*$/', $a) === false)
	return;
 $sta = "../pool/workers/$a";
 if (file_exists($sta))
	echo file_get_contents($sta);
}
go();
?>
</body></html>
