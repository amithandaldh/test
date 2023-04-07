<?php
$domain = (isset($_SERVER) && isset($_SERVER['HTTP_HOST'])) ? $_SERVER['HTTP_HOST'] : '';
$isHttps = (isset($_SERVER) && ((isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') || (isset($_SERVER['HTTPS']) && !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'))) ? TRUE : FALSE;
if (!$isHttps && isset($_SERVER) && isset($_SERVER['HTTP_CF_VISITOR']) && strpos($_SERVER['HTTP_CF_VISITOR'], 'https') !== false ) { 
    $isHttps = TRUE;
} 

$httpProtocol = ($isHttps) ? 'https' : 'http';

return [
    'adminEmail' => 'admin@example.com',
    'supportEmail' => 'support@example.com',
    'senderEmail' => 'noreply@example.com',
    'senderName' => 'Example.com mailer',
    'user.passwordResetTokenExpire' => 3600,
    'user.passwordMinLength' => 8,
    'staticHttpPath' => $httpProtocol.'://'.$domain.'/static',
    'cacheBustingTimestamp' => '2022053001',
];
