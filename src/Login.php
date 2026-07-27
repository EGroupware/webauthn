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

use EGroupware\Api;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

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
			$repo = new PublicKeyCredentialSourceRepository();

			// RP Entity
			$rpEntity = PublicKeyCredentialRpEntity::own();

			// User Entity
			$userEntity = PublicKeyCredentialUserEntity::get($account_id);

			$registeredPublicKeyCredentialSources = $repo->findAllForUserEntity($userEntity);

			if (count($registeredPublicKeyCredentialSources))
			{
				$registeredPublicKeyCredentialDescriptors = array_map(static function(CredentialRecord $item) {
					return $item->getPublicKeyCredentialDescriptor();
				}, $registeredPublicKeyCredentialSources);

				// Public Key Credential Request Options
				$publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
					random_bytes(32),
					$rpEntity->id,
					$registeredPublicKeyCredentialDescriptors,
					PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED
				);
				$encodedOptions = PublicKeyCredentialSourceRepository::serializer()->serialize($publicKeyCredentialRequestOptions, 'json');

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
		$userEntity = PublicKeyCredentialUserEntity::get($GLOBALS['egw_info']['user']['account_id'] ??
			Api\Accounts::getInstance()->name2id($_POST['login']));
		$repo = new PublicKeyCredentialSourceRepository();
		try {
			$registeredPublicKeyCredentialSources = $repo->findAllForUserEntity($userEntity);
			if (count($registeredPublicKeyCredentialSources))
			{
				$data['errors'][self::APP] = lang('WebAuthN token or passkey required!');
			}
		}
		catch (Api\Exception\NotFound $e) {
			// user has not WebAuthN token registered, therefore NOT setting the above error
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
		$serializer = PublicKeyCredentialSourceRepository::serializer();
		$publicKeyCredentialRequestOptions = $serializer->deserialize($_SESSION['publicKeyCredentialRequestOptions'],
			PublicKeyCredentialRequestOptions::class, 'json');
		//error_log("PublicKeyCredentialRequestOptions from session=".json_encode($publicKeyCredentialRequestOptions));

		// User Entity
		$userEntity = PublicKeyCredentialUserEntity::get($GLOBALS['egw']->session->account_id);

		// Retrieve the data sent by the device
		$response = base64_decode($_POST['credentialsResponse']);
		//error_log("data from request=$response");

		try {
			$publicKeyCredential = $serializer->deserialize($response, PublicKeyCredential::class, 'json');
			if (!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse)
			{
				throw new \UnexpectedValueException('Not an assertion response');
			}

			// credential record as stored/updated by a previous registration
			$credentialRecord = $repo->findOneByCredentialId($publicKeyCredential->rawId);
			if (!$credentialRecord)
			{
				throw new Api\Exception\NotFound('Unknown credential');
			}

			// current request scheme+host, used both as fallback rpId and for strict origin checking
			$scheme = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http';
			$host = preg_replace('/:.*$/', '', $_SERVER['HTTP_HOST']);

			$ceremonyStepManagerFactory = new CeremonyStepManagerFactory();
			$ceremonyStepManagerFactory->setAllowedOrigins([$scheme.'://'.$_SERVER['HTTP_HOST']]);

			$validator = AuthenticatorAssertionResponseValidator::create($ceremonyStepManagerFactory->requestCeremony());

			// check() mutates $credentialRecord's counter in place; must be persisted explicitly -
			// unlike webauthn-lib v3's Server, v5's validator no longer holds/updates the repository itself
			$validator->check(
				$credentialRecord,
				$publicKeyCredential->response,
				$publicKeyCredentialRequestOptions,
				$host,
				$userEntity->id
			);
			$repo->saveCredentialSource($credentialRecord);

			// report our now verified factor
			$data['factors'][self::APP] = true;
			unset($data['errors'][self::APP]);
		}
		catch (\Throwable $throwable)
		{
			_egw_log_exception($throwable);
			$data['errors'][self::APP] = $throwable->getMessage();
		}
	}
}
