<?php
declare(strict_types=1);

namespace Lookyman\Security\Tests;

use Defuse\Crypto\Key;
use Lookyman\Security\Passwords;

class PasswordsTest extends \PHPUnit_Framework_TestCase
{
	public function testHashVerify()
	{
		$key = Key::createNewRandomKey();
		$password = 'foo';
		self::assertTrue(Passwords::verify($password, Passwords::hash($password, $key), $key));
	}

	/**
	 * @expectedException \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
	 */
	public function testHashVerifyWrongKey()
	{
		$key1 = Key::createNewRandomKey();
		$key2 = Key::createNewRandomKey();
		$password = 'foo';
		Passwords::verify($password, Passwords::hash($password, $key1), $key2);
	}

	public function testHashVerifyWrongPassword()
	{
		$key = Key::createNewRandomKey();
		self::assertFalse(Passwords::verify('bar', Passwords::hash('foo', $key), $key));
	}

	public function testGetInfo()
	{
		$key = Key::createNewRandomKey();
		$info = Passwords::getInfo(Passwords::hash('foo', $key), $key);
		self::assertArrayHasKey('algo', $info);
		self::assertEquals(PASSWORD_DEFAULT, $info['algo']);
		self::assertArrayHasKey('algoName', $info);
		self::assertInternalType('string', $info['algoName']);
		self::assertArrayHasKey('options', $info);
		self::assertInternalType('array', $info['options']);
		self::assertArrayHasKey('cost', $info['options']);
		self::assertEquals(Passwords::COST_DEFAULT, $info['options']['cost']);
	}

	public function testNeedsRehash()
	{
		$key = Key::createNewRandomKey();
		self::assertFalse(Passwords::needsRehash(Passwords::hash('foo', $key), $key));
		self::assertTrue(Passwords::needsRehash(Passwords::hash('foo', $key, Passwords::COST_DEFAULT - 1), $key));
	}
}
