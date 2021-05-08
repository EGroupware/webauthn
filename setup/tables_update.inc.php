<?php
/**
 * EGroupware - Setup
 * https://www.egroupware.org
 * Created by eTemplates DB-Tools written by ralfbecker@outdoor-training.de
 *
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 * @package webauthn
 * @subpackage setup
 */

/**
 * Bump version to 20.1
 *
 * @return string
 */
function webauthn_upgrade19_1()
{
	return $GLOBALS['setup_info']['webauthn']['currentver'] = '20.1';
}

/**
 * Bump version to 21.1
 *
 * @return string
 */
function webauthn_upgrade20_1()
{
	return $GLOBALS['setup_info']['webauthn']['currentver'] = '21.1';
}
