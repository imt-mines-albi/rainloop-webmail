<?php

class LDAPLoginMappingPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	/**
	 * @var array
	 */
	private $aDomains = array();

	/**
	 * @var string
	 */
	private $sSearchDomain = '';

	/**
	 * @var string
	 */
	private $sHostName = '127.0.0.1';

	/**
	 * @var int
	 */
	private $iHostPort = 389;

	/**
	 * @var string
	 */
	private $sUsersDn = '';

	/**
	 * @var string
	 */
	private $sObjectClass = 'inetOrgPerson';

	/**
	 * @var string
	 */
	private $sLoginField = 'uid';

	/**
	 * @var string
	 */
	private $sEmailField = 'mail';

	/**
	 * @var \MailSo\Log\Logger
	 */
	private $oLogger = null;

	public function Init()
	{
		$this->addHook('filter.login-credentials', 'FilterLoginСredentials');
	}

	/**
	 * @return string
	 */
	public function Supported()
	{
		if (!\function_exists('ldap_connect'))
		{
			return 'The LDAP PHP extension must be installed to use this plugin';
		}

		return '';
	}

	/**
	 * @param string $sEmail
	 * @param string $sLogin
	 * @param string $sPassword
	 *
	 * @throws \RainLoop\Exceptions\ClientException
	 */
	public function FilterLoginСredentials(&$sEmail, &$sLogin, &$sPassword)
	{
		$this->oLogger = \MailSo\Log\Logger::SingletonInstance();

		$this->aDomains = \explode(',', $this->Config()->Get('plugin', 'domains', ''));
		$this->sSearchDomain = \trim($this->Config()->Get('plugin', 'search_domain', ''));
		$this->sHostName = \trim($this->Config()->Get('plugin', 'hostname', ''));
		$this->iHostPort = (int) $this->Config()->Get('plugin', 'port', 389);
		$this->sUsersDn = \trim($this->Config()->Get('plugin', 'users_dn', ''));
		$this->sObjectClass = \trim($this->Config()->Get('plugin', 'object_class', ''));
		$this->sLoginField = \trim($this->Config()->Get('plugin', 'login_field', ''));
		$this->sEmailField = \trim($this->Config()->Get('plugin', 'mail_field', ''));

		if (0 < \strlen($this->sObjectClass) && 0 < \strlen($this->sEmailField))
		{
			$sResult = $this->ldapSearch($sEmail);
			if ( is_array($sResult) ) {
				$sLogin = $sResult['login'];
				$sEmail = $sResult['email'];
			}
		}
	}

	/**
	 * @return array
	 */
	public function configMapping()
	{
		return array(
/*
			\RainLoop\Plugins\Property::NewInstance('domain')->SetLabel('LDAP enabled domain')
			->SetDefaultValue('example.com'),
*/
			\RainLoop\Plugins\Property::NewInstance('domains')->SetLabel('LDAP enabled domains')
				->SetDefaultValue('example1.com,example2.com'),
			\RainLoop\Plugins\Property::NewInstance('search_domain')->SetLabel('Forced domain')
				->SetDescription('Force this domain email for LDAP search')
				->SetDefaultValue('example.com'),
			\RainLoop\Plugins\Property::NewInstance('hostname')->SetLabel('LDAP hostname')
				->SetDefaultValue('127.0.0.1'),
			\RainLoop\Plugins\Property::NewInstance('port')->SetLabel('LDAP port')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::INT)
				->SetDefaultValue(389),
/*
			\RainLoop\Plugins\Property::NewInstance('access_dn')->SetLabel('Access dn (login)')
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('access_password')->SetLabel('Access password')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::PASSWORD)
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('users_dn_format')->SetLabel('Users DN format')
				->SetDescription('LDAP users dn format. Supported tokens: {email}, {login}, {domain}, {domain:dc}, {imap:login}, {imap:host}, {imap:port}')
				->SetDefaultValue('ou=People,dc=domain,dc=com'),
*/
			\RainLoop\Plugins\Property::NewInstance('users_dn')->SetLabel('Search base DN')
				->SetDescription('LDAP users search base DN. No tokens.')
				->SetDefaultValue('ou=People,dc=domain,dc=com'),
			\RainLoop\Plugins\Property::NewInstance('object_class')->SetLabel('objectClass value')
				->SetDefaultValue('inetOrgPerson'),
/*			\RainLoop\Plugins\Property::NewInstance('name_field')->SetLabel('Name field')
->SetDefaultValue('givenname'),
 */
			\RainLoop\Plugins\Property::NewInstance('login_field')->SetLabel('Login field')
				->SetDefaultValue('uid'),
			\RainLoop\Plugins\Property::NewInstance('mail_field')->SetLabel('Mail field')
				->SetDefaultValue('mail'),
/*			\RainLoop\Plugins\Property::NewInstance('allowed_emails')->SetLabel('Allowed emails')
				->SetDescription('Allowed emails, space as delimiter, wildcard supported. Example: user1@domain1.net user2@domain1.net *@domain2.net')
				->SetDefaultValue('*')
*/
		);
	}

	/**
	 * @param string $sEmailOrLogin
	 *
	 * @return string
	 */
	private function ldapSearch($sEmail)
	{
		$bFound = FALSE;
		foreach ( $this->aDomains as $sDomain ) {
			$sRegex = '/^[a-z0-9._-]+@' . preg_quote(trim($sDomain)) . '$/i';
			$this->oLogger->Write('DEBUG regex ' . $sRegex, \MailSo\Log\Enumerations\Type::INFO, 'LDAP');
			if ( preg_match($sRegex, $sEmail) === 1) {
				$bFound = TRUE;
				break;
			}
		}
		if ( !$bFound ) {
			$this->oLogger->Write('preg_match: no match in "' . $sEmail . '" for /^[a-z0-9._-]+@{configured-domains}$/i', \MailSo\Log\Enumerations\Type::INFO, 'LDAP');
			return FALSE;
		}
		$sLogin = \MailSo\Base\Utils::GetAccountNameFromEmail($sEmail);

		$this->oLogger->Write('ldap_connect: trying...', \MailSo\Log\Enumerations\Type::INFO, 'LDAP');

		$oCon = @\ldap_connect($this->sHostName, $this->iHostPort);
		if (!$oCon) return FALSE;

		$this->oLogger->Write('ldap_connect: connected', \MailSo\Log\Enumerations\Type::INFO, 'LDAP');

		@\ldap_set_option($oCon, LDAP_OPT_PROTOCOL_VERSION, 3);

		if (!@\ldap_bind($oCon)) {
			$this->logLdapError($oCon, 'ldap_bind');
			return FALSE;
		}
		$sSearchDn = $this->sUsersDn;
		$aItems = array($this->sLoginField, $this->sEmailField);
		if ( 0 < \strlen($this->sSearchDomain) ) {
			$sFilter = '(&(objectclass='.$this->sObjectClass.')(|('.$this->sEmailField.'='.$sLogin.'@'.$this->sSearchDomain.')('.$this->sLoginField.'='.$sLogin.')))';

		} else {
			$sFilter = '(&(objectclass='.$this->sObjectClass.')(|('.$this->sEmailField.'='.$sEmail.')('.$this->sLoginField.'='.$sLogin.')))';
		}
		$this->oLogger->Write('ldap_search: start: '.$sSearchDn.' / '.$sFilter, \MailSo\Log\Enumerations\Type::INFO, 'LDAP');
		$oS = @\ldap_search($oCon, $sSearchDn, $sFilter, $aItems, 0, 30, 30);
		if (!$oS) {
			$this->logLdapError($oCon, 'ldap_search');
			return FALSE;
		}
		$aEntries = @\ldap_get_entries($oCon, $oS);
		if (!is_array($aEntries)) {
			$this->logLdapError($oCon, 'ldap_get_entries');
			return FALSE;
		}
		if (!isset($aEntries[0])) {
			$this->logLdapError($oCon, 'ldap_get_entries (no result)');
			return FALSE;
		}
		if (!isset($aEntries[0][$this->sLoginField][0])) {
			$this->logLdapError($oCon, 'ldap_get_entries (no login)');
			return FALSE;
		}
		if (!isset($aEntries[0][$this->sEmailField][0])) {
			$this->logLdapError($oCon, 'ldap_get_entries (no mail)');
			return FALSE;
		}
		$sLogin = $aEntries[0][$this->sLoginField][0];
		$sEmail = $aEntries[0][$this->sEmailField][0];
		$this->oLogger->Write('ldap_search: found "' . $this->sLoginField . ': '.$sLogin . '" and "' . $this->sEmailField . ': '.$sEmail . '"');

		return array(
			'login' => $sLogin,
			'email' => $sEmail,
		);
	}

	/**
	 * @param mixed $oCon
	 * @param string $sCmd
	 *
	 * @return string
	 */
	private function logLdapError($oCon, $sCmd)
	{
		if ($this->oLogger)
		{
			$sError = $oCon ? @\ldap_error($oCon) : '';
			$iErrno = $oCon ? @\ldap_errno($oCon) : 0;

			$this->oLogger->Write($sCmd.' error: '.$sError.' ('.$iErrno.')',
				\MailSo\Log\Enumerations\Type::WARNING, 'LDAP');
		}
	}

}
