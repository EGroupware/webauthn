<?php
/**
 * EGroupware WebAuthn
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package webauthn
 * @license https://www.egroupware.org/EPL EPL - EGroupware EPL License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/web-auth/webauthn-framework
 */

namespace EGroupware\WebAuthn;

// explicitly include autoloader for our own vendor directory
include __DIR__.'/../vendor/autoload.php';

use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Server;
use Zend\Diactoros\ServerRequestFactory;
use EGroupware\Api;

/**
 * Display tokens of current user under Preferences >> Password & Security
 */
class Login
{
	const APP = 'webauthn';

	/**
	 * Answers login_page hook
	 *
	 * @param array $data
	 */
	public static function page(array $data)
	{
		unset($data);	// not used, but required by function signature

		Api\Framework::includeJS('/webauthn/js/login.js');
	}

	/**
	 * Check if user has WebAuthn / U2F token registered and return information to send to browser
	 *
	 * @param array $data
	 * @return string JSON encoded information for login.js
	 */
	public static function ajax_login(array $data)
	{
		if (empty($data['2fa_code']) && !empty($data['login']) &&
			($account_id = Api\Accounts::getInstance()->name2id($data['login'])))
		{
			// check if we already have another factor (e.g. IP-address is configured and matching)
			$factors = $errors = [];
			$data = ['factors' => &$factors, 'errors' => &$errors, 'location' => 'multifactor_policy'];
			try {
				Api\Hooks::process($data, [], true);
				if (count($factors)) return;	// IP-address matches, no further factor(s) required
			}
			catch (\Exception $e) {
				_egw_log_exception($e);
			}

			// Credential Repository
			$publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

			// RP Entity
			$rpEntity = PublicKeyCredentialRpEntity::own();

			// New Server class introduced in v2.1
			$server = new Server(
				$rpEntity,
				$publicKeyCredentialSourceRepository,
				null
			);

			// User Entity
			$userEntity = PublicKeyCredentialUserEntity::get($account_id);

			$repo = new PublicKeyCredentialSourceRepository();
			$registeredPublicKeyCredentialSources = $repo->findAllForUserEntity($userEntity);

			if (count($registeredPublicKeyCredentialSources))
			{
				$registeredPublicKeyCredentialDescriptors = array_map(static function(PublicKeyCredentialSource $item) {
					return $item->getPublicKeyCredentialDescriptor();
				}, $registeredPublicKeyCredentialSources);

				// Public Key Credential Request Options
				$publicKeyCredentialRequestOptions = $server->generatePublicKeyCredentialRequestOptions(
					PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
					$registeredPublicKeyCredentialDescriptors
				);
				$encodedOptions = json_encode($publicKeyCredentialRequestOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

				// we need to create a session here, to be able to store the options
				session_name(Api\Session::EGW_SESSION_NAME);
				ini_set('session.use_cookies', 0);	// disable the automatic use of cookies, as it uses the path / by default
				session_id(Api\Session::get_sessionid());
				Api\Session::cache_control();
				if (session_status() === PHP_SESSION_NONE) session_start();
				$_SESSION['publicKeyCredentialRequestOptions'] = $encodedOptions;
				Api\Session::egw_setcookie(Api\Session::EGW_SESSION_NAME, session_id());

				//error_log(__METHOD__."() values=".json_encode($data)." returning $encodedOptions");
				return $encodedOptions;
			}
		}
	}

	/**
	 * Answers multifactor_policy hook to check login response and set second factor
	 *
	 * @param array $data with arrays for keys "factors" and "errors" to report our factor or errors
	 */
	public static function multifactor(array $data)
	{
		//error_log(__METHOD__."(".json_encode($data).") _POST[credentialsResponse]=$_POST[credentialsResponse]");

		// Check if user has WebAuthN configured
		if (PublicKeyCredentialRpEntity::own())
		{
			$data['errors'][self::APP] = lang('WebAuthN token or passkey required!');
		}

		if (empty($_SESSION['publicKeyCredentialRequestOptions']))
		{
			//error_log(__METHOD__."() credentialsRequestOptions (from session) missing");
			return;
		}
		if (empty($_POST['credentialsResponse']))
		{
			//error_log(__METHOD__."() credentialsResponse missing, probably aborted by user");
			$data['errors'][self::APP] = 'credentials response missing, probably aborted by user';
			return;
		}
		$publicKeyCredentialRequestOptions =  PublicKeyCredentialRequestOptions::createFromString($_SESSION['publicKeyCredentialRequestOptions']);
		//error_log("PublicKeyCredentialRequestOptions from session=".json_encode($publicKeyCredentialRequestOptions));

		// Credential Repository
		$publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

		// RP Entity
		$rpEntity = PublicKeyCredentialRpEntity::own();

		// New Server class introduced in v2.1
		$server = new Server(
			$rpEntity,
			$publicKeyCredentialSourceRepository,
			null
		);

		// User Entity
		$userEntity = PublicKeyCredentialUserEntity::get($GLOBALS['egw']->session->account_id);

		// Retrieve de data sent by the device
		$response = base64_decode($_POST['credentialsResponse']);
		//error_log("data from request=$response");


		try {
			// We init the PSR7 Request object
			$psr7Request = ServerRequestFactory::fromGlobals();
			$server->loadAndCheckAssertionResponse(
				$response,
				$publicKeyCredentialRequestOptions,
				$userEntity,
				$psr7Request
			);

			// report our now verified factor
			$data['factors'][self::APP] = true;
			unset($data['errors'][self::APP]);
		}
		catch (Throwable $throwable)
		{
			_egw_log_exception($throwable);
			$data['errors'][self::APP] = $throwable->getMessage();
		}
	}
}