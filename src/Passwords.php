<?php
declare(strict_types=1);

namespace Lookyman\Security;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;
use ParagonIE\ConstantTime\Base64;

/**
 * Wraps PHP's password_* functions in authenticated encryption.
 */
final class Passwords
{
	const COST_DEFAULT = 10;

	/**
	 * @see https://secure.php.net/manual/en/function.password-get-info.php
	 *
	 * @param string $hash
	 * @param Key $key
	 * @return array
	 * @throws EnvironmentIsBrokenException
	 * @throws WrongKeyOrModifiedCiphertextException
	 */
	public static function getInfo(string $hash, Key $key): array
	{
		return \password_get_info(Crypto::decrypt($hash, $key));
	}

	/**
	 * @see https://secure.php.net/manual/en/function.password-hash.php
	 *
	 * @param string $password
	 * @param Key $key
	 * @param int $cost
	 * @return string
	 * @throws EnvironmentIsBrokenException
	 * @throws \Exception
	 */
	public static function hash(string $password, Key $key, int $cost = self::COST_DEFAULT): string
	{
		$hash = \password_hash(Base64::encode(\hash('sha384', $password, true)), PASSWORD_DEFAULT, ['cost' => $cost]);
		if ($hash === false) {
			// @codeCoverageIgnoreStart
			throw new \Exception('Unknown hashing error');
			// @codeCoverageIgnoreEnd
		}
		return Crypto::encrypt($hash, $key);
	}

	/**
	 * @see https://secure.php.net/manual/en/function.password-needs-rehash.php
	 *
	 * @param string $hash
	 * @param Key $key
	 * @param int $cost
	 * @return bool
	 * @throws EnvironmentIsBrokenException
	 * @throws WrongKeyOrModifiedCiphertextException
	 */
	public static function needsRehash(string $hash, Key $key, int $cost = self::COST_DEFAULT): bool
	{
		return \password_needs_rehash(Crypto::decrypt($hash, $key), PASSWORD_DEFAULT, ['cost' => $cost]);
	}

	/**
	 * @see https://secure.php.net/manual/en/function.password-verify.php
	 *
	 * @param string $password
	 * @param string $hash
	 * @param Key $key
	 * @return bool
	 * @throws EnvironmentIsBrokenException
	 * @throws WrongKeyOrModifiedCiphertextException
	 */
	public static function verify(string $password, string $hash, Key $key): bool
	{
		return \password_verify(Base64::encode(\hash('sha384', $password, true)), Crypto::decrypt($hash, $key));
	}
}
