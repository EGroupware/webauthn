<?php
/**
 * EGroupware WebAuthn
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package webauthn
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/web-auth/webauthn-framework
 */

namespace EGroupware\WebAuthn;

use Cose\Algorithm\Manager as CoseAlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use EGroupware\Api;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;

/**
 * Register and display tokens of current user under Preferences >> Password & Security
 */
class Register
{
	const APP = 'webauthn';

	/**
	 * Answers preferences_password_security hook
	 *
	 * @param array $data
	 */
	public static function security(array $data)
	{
		unset($data);	// not used, but required by function signature

		Api\Translation::add_app(self::APP);

		$registrationOptions = self::registrationOptions();
		Api\Framework::includeJS('/webauthn/js/app.js');

		return [
			'label' =>	'WebAuthn',
			'title' =>	'WebAuthn / U2F tokens',
			'name' => 'webauthn.tokens',
			'prepend' => false,
			'data' => [
				'registrationOptions' => $registrationOptions,
				'webauthn' => [
					'get_rows' => __CLASS__.'::getTokens',
					'no_cat' => true,
					'no_filter' => true,
					'no_filter2' => true,
					'filter_no_lang' => true,
					'order' => 'pubkey_updated',
					'sort' => 'DESC',
					'row_id' => 'pubkey_id',
					'default_cols' => '!pubkey_credential_id',
					'actions' => self::tokenActions(),
				],
			],
			'preserve' => [
				'registrationOptions' => $registrationOptions,
			],
			'sel_options' => [
			],
			'save_callback' => __CLASS__.'::action',
		];
	}

	/**
	 * Get options for creation request
	 *
	 * @return string JSON encoded options
	 */
	protected static function registrationOptions()
	{
		// Credential Repository
		$publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

		// RP Entity
		$rpEntity = PublicKeyCredentialRpEntity::own();

		// User Entity
		$userEntity = PublicKeyCredentialUserEntity::current();

		$registeredPublicKeyCredentialSources = $publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);
		$registeredPublicKeyCredentialDescriptors = array_map(static function(CredentialRecord $item) {
			return $item->getPublicKeyCredentialDescriptor();
		}, $registeredPublicKeyCredentialSources);

		// signature algorithms we accept to sign the new credential (webauthn-lib no longer
		// derives this automatically - mirrors CeremonyStepManagerFactory's own default pair)
		$algorithmManager = CoseAlgorithmManager::create()->add(ES256::create(), RS256::create());
		$pubKeyCredParams = [];
		foreach($algorithmManager->all() as $algorithm)
		{
			$pubKeyCredParams[] = PublicKeyCredentialParameters::createPk($algorithm::identifier());
		}

		$publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
			$rpEntity,
			$userEntity,
			random_bytes(32),
			$pubKeyCredParams,
			AuthenticatorSelectionCriteria::create(),
			PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
			$registeredPublicKeyCredentialDescriptors
		);

		return PublicKeyCredentialSourceRepository::serializer()->serialize($publicKeyCredentialCreationOptions, 'json');
	}

	/**
	 * Process token registration response from browser
	 *
	 * @param string $response
	 * @param string $options
	 */
	protected static function registration($response, $options)
	{
		$serializer = PublicKeyCredentialSourceRepository::serializer();
		$publicKeyCredentialCreationOptions = $serializer->deserialize($options, PublicKeyCredentialCreationOptions::class, 'json');
		//error_log("publicKeyCredentialCreationOptions from session=".json_encode($publicKeyCredentialCreationOptions));

		// Retrieve the data sent by the device
		$data = base64_decode($response);
		//error_log("data from request=$data");

		try {
			$publicKeyCredential = $serializer->deserialize($data, PublicKeyCredential::class, 'json');
			if (!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse)
			{
				throw new \UnexpectedValueException('Not an attestation response');
			}

			// current request scheme+host, used both as fallback rpId and for strict origin checking
			// (must use the same proxy-aware helpers as the rest of EGroupware, not raw $_SERVER
			// values - behind a reverse proxy terminating TLS, $_SERVER['HTTPS'] is unset, which
			// made the allowed origin "http://..." while the browser's real origin is "https://...")
			$scheme = Api\Header\Http::schema();
			$host = preg_replace('/:.*$/', '', Api\Header\Http::host());

			$ceremonyStepManagerFactory = new CeremonyStepManagerFactory();
			$ceremonyStepManagerFactory->setAllowedOrigins([$scheme.'://'.Api\Header\Http::host()]);

			$validator = AuthenticatorAttestationResponseValidator::create($ceremonyStepManagerFactory->creationCeremony());

			// Check the response against the request
			$credentialRecord = $validator->check($publicKeyCredential->response, $publicKeyCredentialCreationOptions, $host);

			// Everything is OK here.

			// Persist the credential record using the Public Key Credential Source repository
			$publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();
			$publicKeyCredentialSourceRepository->saveCredentialSource($credentialRecord);
			Api\Framework::message(lang('WebAuthn / U2F token registered'));
		}
		catch (\Throwable $e) {
			_egw_log_exception($e);
			Api\Framework::message($e->getMessage(), 'error');
		}
	}

	/**
	 * Callback to run for actions (general on all form posts)
	 *
	 * User password is already checked!
	 *
	 * @param array $content
	 * @return string with success message
	 * @throws Exception on error
	 */
	public static function action(array $content)
	{
		// user registered a new token
		if (is_array($content) && !empty($content['registrationResponse']))
		{
			self::registration($content['registrationResponse'], $content['registrationOptions']);
		}

		if (is_array($content) && $content['tabs'] === 'webauthn.tokens' && $content['webauthn']['selected'])
		{
			switch($content['webauthn']['action'])
			{
				case 'delete':
					$token_repo = new PublicKeyCredentialSourceRepository();
					$token_repo->delete(['pubkey_id' => $content['webauthn']['selected']]);
					Api\Framework::message((count($content['webauthn']['selected']) > 1 ?
						count($content['webauthn']['selected']).' ' : '').lang('Token deleted.'));
					break;
			}
		}
		unset($content['webauthn']['selected'], $content['webauthn']['action'], $content['registrationResponse']);
	}

	/**
	 * Query tokens for nextmatch widget
	 *
	 * @param array $query with keys 'start', 'search', 'order', 'sort', 'col_filter'
	 *	For other keys like 'filter', 'cat_id' you have to reimplement this method in a derived class.
	 * @param array &$rows returned rows/competitions
	 * @param array &$readonlys eg. to disable buttons based on acl, not use here, maybe in a derived class
	 * @return int number of rows found
	 */
	public static function getTokens(array $query, array &$rows, array &$readonlys)
	{
		$token_repo = new PublicKeyCredentialSourceRepository();
		$query['col_filter']['account_id'] = $GLOBALS['egw_info']['user']['account_id'];
		if (($ret = $token_repo->get_rows($query, $rows, $readonlys)))
		{
			foreach($rows as $key => &$row)
			{
				if (!is_int($key)) continue;

				$row += json_decode($row['pubkey_json'], true);
				unset($row['pubkey_json']);
			}
		}
		return $ret;
	}

	/**
	 * Get actions for tokens
	 */
	protected static function tokenActions()
	{
		return [
			'delete' => array(
				'caption' => 'Delete',
				'allowOnMultiple' => true,
				'confirm' => 'Delete this token',
			),
		];
	}
}
