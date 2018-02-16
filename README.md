# php-whois

PHP class to retrieve WHOIS information.

## Example of usage

```php

<?php

$sld = 'reg.ru';

$domain = new Phois\Whois\Whois($sld);

$whois_answer = $domain->info();

echo $whois_answer;

if ($domain->isAvailable()) {
    echo "Domain is available\n";
} else {
    echo "Domain is registered\n";
}

```

## Proxy

```php
$sld = 'reg.ru';

$domain = new Phois\Whois\Whois($sld, [
    'host' => '127.0.0.1',
    'port' => '30000',
    'user' => 'user',
    'pass' => 'secret'
]);
```