Lookyman/Security
==========================

Wraps PHP's password_* functions in authenticated encryption.

[![Build Status](https://travis-ci.org/lookyman/security.svg?branch=master)](https://travis-ci.org/lookyman/security)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/lookyman/security/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/lookyman/security/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/lookyman/security/badge.svg?branch=master)](https://coveralls.io/github/lookyman/security?branch=master)
[![Downloads](https://img.shields.io/packagist/dt/lookyman/security.svg)](https://packagist.org/packages/lookyman/security)
[![Latest stable](https://img.shields.io/packagist/v/lookyman/security.svg)](https://packagist.org/packages/lookyman/security)


Installation
------------

```sh
composer require lookyman/security
```


Usage
-----

```php
$key = \Defuse\Crypto\Key::createNewRandomKey();
$hash = \Lookyman\Security\Passwords::hash('abc123', $key);
echo \Lookyman\Security\Passwords::verify('abc123', $hash, $key) ? 'success' : 'failure';
```
