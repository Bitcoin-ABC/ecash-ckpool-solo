<?php
#
# FYI see PEAR::Mail for functions to add for batch email
#
global $eol;
$eol = "\r\n";
#
function fullsend($to, $subject, $message, $headers, $extra = null)
{
 if ($extra == null)
	$ret = mail($to, $subject, $message, $headers);
 else
	$ret = mail($to, $subject, $message, $headers, $extra);

 if ($ret == false)
	error_log("CKPWARN: ".gmdate("Y-m-d H:i:s \\U\\T\\C").
		  " sendmail failed? to: '$to'");

 return $ret;
}
#
function sendnoheader($to, $subject, $message, $emailinfo)
{
 global $eol;

 if (!isset($emailinfo['KNoReply']))
	return false;

 $noreply = $emailinfo['KNoReply'];

 $headers = "From: $noreply$eol";
 $headers .= "X-Mailer: .";

 return fullsend($to, $subject, $message, $headers, "-f$noreply");
}
#
function dontReply($emailinfo)
{
 global $eol;

 if (!isset($emailinfo['KWebURL']))
	return false;

 $web = $emailinfo['KWebURL'];

 $message = "P.S. don't reply to this e-mail, no one will get the reply$eol";
 $message .= "There is a contact e-mail address (that changes often)$eol";
 $message .= "at $web/ or visit us on FreeNode IRC #ckpool$eol";

 return $message;
}
#
function emailEnd($the, $whoip, $emailinfo)
{
 global $eol;

 $ret = dontReply($emailinfo);
 if ($ret === false)
	return false;

 $message = "This $the was made '".gmdate("Y-M-d H:i:s \\U\\T\\C");
 $message .= "' by '$whoip'$eol$eol";
 $message .= $ret;

 return $message;
}
#
function passWasReset($to, $whoip, $emailinfo)
{
 global $eol;

 if (!isset($emailinfo['KWebURL']))
	return false;

 $web = $emailinfo['KWebURL'];

 $ret = emailEnd('reset', $whoip, $emailinfo);
 if ($ret === false)
	return false;

 $message = "Your password has been reset.$eol$eol";
 $message .= $ret;

 return sendnoheader($to, "Password Reset", $message, $emailinfo);
}
#
function passReset($to, $code, $whoip, $emailinfo)
{
 global $eol;

 if (!isset($emailinfo['KWebURL']))
	return false;

 $web = $emailinfo['KWebURL'];

 $ret = emailEnd('password reset', $whoip, $emailinfo);
 if ($ret === false)
	return false;

 $message = "Someone requested to reset your password.$eol$eol";
 $message .= "You can ignore this message since nothing has changed yet,$eol";
 $message .= "or click on the link below to reset your password.$eol";
 $message .= "$web/index.php?k=reset&code=$code$eol$eol";
 $message .= $ret;

 return sendnoheader($to, "Password Reset", $message, $emailinfo);
}
#
# getOpts required for email
# If they aren't all setup in the DB then email functions will return false
function emailOptList()
{
 return 'KWebURL,KNoReply';
}
#
?>
