<?php

require_once __DIR__ . '/../vendor/autoload.php';

$sld = 'reg.ru';

$domain = new Phois\Whois\Whois($sld, [
    'host' => '127.0.0.1',
    'port' => '30000',
    'user' => 'user',
    'pass' => 'secret'
], 60, 60);

$whois_answer = $domain->info();

echo $whois_answer;
