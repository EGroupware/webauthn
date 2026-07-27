<?php
/**
 * EGroupware WebAuthn - tests for the User entity factory
 *
 * @link https://www.egroupware.org
 * @package webauthn
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\WebAuthn;

require_once __DIR__.'/../../api/tests/LoggedInTest.php';

use EGroupware\Api;
use EGroupware\Api\LoggedInTest;

/**
 * PublicKeyCredentialUserEntity::current()/::get() build the WebAuthn "user handle" used to
 * scope credentials to an EGroupware account (account_id + install_id, so credentials from
 * different EGroupware installs never collide). That handle is round-tripped through the
 * browser and back, so its format must stay stable across a webauthn-lib upgrade.
 */
class PublicKeyCredentialUserEntityTest extends LoggedInTest
{
	/**
	 * current() must reflect the logged in demo user from doc/phpunit.xml.
	 */
	public function testCurrentUsesLoggedInUser()
	{
		$userEntity = PublicKeyCredentialUserEntity::current();

		$account_id = $GLOBALS['egw_info']['user']['account_id'];
		$install_id = $GLOBALS['egw_info']['server']['install_id'];

		$this->assertSame('@'.$GLOBALS['egw_info']['user']['account_lid'], $userEntity->name);
		$this->assertSame($account_id.'-'.$install_id, $userEntity->id);
		$this->assertSame($GLOBALS['egw_info']['user']['account_fullname'], $userEntity->displayName);
	}

	/**
	 * get($account_id) must build the same kind of entity for an arbitrary (valid) account,
	 * not just the currently logged in one (used eg. for a not-yet-authenticated login attempt).
	 */
	public function testGetValidAccount()
	{
		$account_id = $GLOBALS['egw_info']['user']['account_id'];
		$account = Api\Accounts::getInstance()->read($account_id);

		$userEntity = PublicKeyCredentialUserEntity::get($account_id);

		$this->assertSame('@'.$account['account_lid'], $userEntity->name);
		$this->assertSame($account_id.'-'.$GLOBALS['egw_info']['server']['install_id'], $userEntity->id);
		$this->assertSame($account['account_fullname'], $userEntity->displayName);
	}

	/**
	 * get() must fail loudly for an account_id that does not exist - Login::multifactor()
	 * relies on catching Api\Exception\NotFound to mean "no WebAuthn configured", so silently
	 * returning a bogus entity instead would turn into a broken/false 2FA check.
	 */
	public function testGetInvalidAccountThrows()
	{
		$this->expectException(Api\Exception\NotFound::class);

		// large id very unlikely to exist as a real account
		PublicKeyCredentialUserEntity::get(999999999);
	}
}
