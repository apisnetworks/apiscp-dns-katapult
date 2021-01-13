<?php declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, July 2020
	 */

	namespace Opcenter\Dns\Providers\Katapult;

	use Auth\Sectoken;
	use GuzzleHttp\Exception\ClientException;
	use Module\Provider\Contracts\ProviderInterface;
	use Opcenter\Dns\Record as BaseRecord;

	class Module extends \Dns_Module implements ProviderInterface
	{
		use \NamespaceUtilitiesTrait;

		/**
		 * apex markers are marked with @
		 */
		protected const HAS_ORIGIN_MARKER = true;
		protected static $permitted_records = [
			'A',
			'AAAA',
			'CAA',
			'CNAME',
			'MX',
			'NS',
			'SRV',
			'TXT'
		];

		// hide showing of NS apex
		public const SHOW_NS_APEX = false;

		protected const AXFR_ATTR_MAP = [
			'A'     => 'ip',
			'AAAA'  => 'ip',
			'CNAME' => 'name',
			'NS'    => 'name',
			'TXT'   => 'data'
		];

		protected $metaCache = [];
		// @var array API credentials
		private $key;

		public function __construct()
		{
			parent::__construct();
			$this->key = $this->getServiceValue('dns', 'key', DNS_PROVIDER_KEY);
			if (!is_array($this->key)) {
				$this->key = [
					'token' => $this->key
				];
			}
		}

		/**
		 * Add a DNS record
		 *
		 * @param string $zone
		 * @param string $subdomain
		 * @param string $rr
		 * @param string $param
		 * @param int    $ttl
		 * @return bool
		 */
		public function add_record(
			string $zone,
			string $subdomain,
			string $rr,
			string $param,
			int $ttl = self::DNS_TTL
		): bool {
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			$api = $this->makeApi();
			$record = new Record($zone, [
				'name'      => $subdomain,
				'rr'        => $rr,
				'parameter' => $param,
				'ttl'       => $ttl
			]);

			try {
				$ret = $api->do('POST', "dns/zones/_/records", ['dns_zone' => ['name' => $zone], 'details' => $this->formatRecord($record)]);
				$record->setMeta('id', $ret['dns_record']['id']);
				$this->addCache($record);
			} catch (ClientException $e) {
				return error("Failed to create record `%s': %s", (string)$record, array_get($this->renderMessage($e), 'description', ''));
			}

			return (bool)$ret;
		}

		protected function canonicalizeRecord(
			string &$zone,
			string &$subdomain,
			string &$rr,
			string &$param,
			int &$ttl = null
		): bool {
			if (!parent::canonicalizeRecord($zone, $subdomain, $rr, $param,
				$ttl))
			{
				return false;
			}
			if ($rr === 'TXT') {
				$param = str_replace('"', '', $param);
			}
			return true;
		}

		private function meld($uri, array $args): string
		{
			if (is_array($uri)) {
				$uri = \ArgumentFormatter::format(...$uri);
			}
			$uri .= false !== strpos($uri, '?') ? '&' : '?';

			$fn = static function ($arr, $carry = '') use (&$fn) {
				$return = [];
				foreach ($arr as $k => $v) {
					$label = $carry ? "${carry}[$k]" : $k;
					if (is_array($v)) {
						$v = implode('&', $fn($v, $label));
						$return[] = $v;
					} else {
						$return[] = $label . '=' . rawurlencode((string)$v);
					}
				}

				return $return;
			};

			return $uri . implode('&', $fn($args));
		}
		/**
		 * @inheritDoc
		 */
		public function remove_record(string $zone, string $subdomain, string $rr, string $param = ''): bool
		{
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			$api = $this->makeApi();

			$id = $this->getRecordId($r = new Record($zone,
				['name' => $subdomain, 'rr' => $rr, 'parameter' => $param]));
			if (!$id) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Record `%s' (rr: `%s', param: `%s')  does not exist", $fqdn, $rr, $param);
			}

			try {
				$api->do('DELETE', "dns/records/${id}");
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Failed to delete record `%s' type %s", $fqdn, $rr);
			}

			array_forget_first(
				$this->zoneCache[$r->getZone()],
				$this->getCacheKey($r),
				static function ($v) use ($id) {
					return $v->getMeta('id') === $id;
				}
			);

			return $api->getResponse()->getStatusCode() === 200;
		}

		/**
		 * Add DNS zone to service
		 *
		 * @param string $domain
		 * @param string $ip
		 * @return bool
		 */
		public function add_zone_backend(string $domain, string $ip): bool
		{
			/**
			 * @var Zones $api
			 */
			$api = $this->makeApi();
			try {
				$resp = $api->do('POST', ['organizations/%(organization)s/dns/zones', ['organization' => $this->organizationLookup()]], [
					'details' => [
						'name' => $domain,
						'ttl'  => self::DNS_TTL,
					]
				]);
			} catch (ClientException $e) {
				return error("Failed to add zone `%s', error: %s", $domain, array_get($this->renderMessage($e), 'description', 'unknown'));
			}

			return true;
		}

		private function organizationLookup(): ?string
		{

			if (isset($this->key['org'])) {
				return $this->key['org'];
			}

			$cache = \Cache_Account::spawn($this->getAuthContext());
			if (($org = $cache->get('dns:katapult.org')) && $org['hash'] === $this->hashKey($this->key['token'])) {
				return $org['id'];
			}

			$api = $this->makeApi();
			$ret = $api->do('GET', 'organizations');
			$id = array_first($ret['organizations'], static function ($v) {
				return $v['suspended'] === false;
			})['id'];

			$cache->set('dns:katapult.org', [
				'id'   => $id,
				'hash' => $this->hashKey($this->key['token'])
			]);

			return $id;
		}

		private function hashKey(string $key): string
		{
			return Sectoken::instantiateContexted($this->getAuthContext())->hash($key);
		}

		/**
		 * Remove DNS zone from nameserver
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function remove_zone_backend(string $domain): bool
		{
			$api = $this->makeApi();
			try {
				$api->do('DELETE', "dns/zones/_/?dns_zone[name]=%(domain)s", ['domain' => $domain]);
			} catch (ClientException $e) {
				return error("Failed to remove zone `%s', error: %s", $domain, array_get($this->renderMessage($e), 'description', 'unknown'));
			}

			return true;
		}

		/**
		 * Get raw zone data
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function zoneAxfr(string $domain): ?string
		{
			// @todo hold records in cache and synthesize AXFR
			$client = $this->makeApi();
			try {
				$records = $client->do('GET', ["dns/zones/_/records?dns_zone[name]=%(domain)s", ['domain' => $domain]]);
				if (!isset($records['dns_records'])) {
					return null;
				}
				$soa = array_get($this->get_records_external('', 'soa', $domain,
					$this->get_hosting_nameservers($domain)), 0, []);

				$ttldef = (int)array_get(preg_split('/\s+/', $soa['parameter'] ?? ''), 6, static::DNS_TTL);
				$preamble = [];
				if ($soa) {
					$preamble = [
						"${domain}.\t${ttldef}\tIN\tSOA\t${soa['parameter']}",
					];
				}
				foreach ($this->get_hosting_nameservers($domain) as $ns) {
					$preamble[] = "${domain}.\t${ttldef}\tIN\tNS\t${ns}.";
				}

			} catch (ClientException $e) {
				if ($e->getResponse()->getStatusCode() === 404) {
					// zone doesn't exist
					return null;
				}
				error('Failed to transfer DNS records from Katapult - try again later. Response code: %d',
					$e->getResponse()->getStatusCode());

				return null;
			}
			$this->zoneCache[$domain] = [];
			foreach ($records['dns_records'] as $r) {
				$rr = strtoupper($r['record_type']);
				$key = rtrim('properties.value.' . (self::AXFR_ATTR_MAP[$rr] ?? ''), '.');
				$attr = array_get($r, $key, null);
				switch ($rr) {
					case 'NS':
						if ($r['name'] === '@') {
							continue 2;
						}
						$parameter = $attr;
						break;
					case 'CAA':
						// @XXX flags always defaults to "0"
						$parameter = $attr['flags'] . ' ' . $attr['property_type'] . ' ' . $attr['property_value'];
						break;
					case 'SRV':
						$parameter = $attr['priority'] . ' ' . $attr['weight'] . ' ' . $attr['port'] . ' ' . $attr['target'];
						break;
					case 'MX':
						$parameter = $attr['priority'] . ' ' . $attr['host'];
						break;
					case 'SSHFP':
						$parameter = $attr['algorithm'] . ' ' . $attr['fingerprint_type'] . ' ' . $attr['fingerprint'];
						break;
					default:
						if (is_scalar($attr)) {
							$parameter = $attr;
						} else {
							error("Unknown record `%s' - this is a bug", $rr);
						}
				}

				$hostname = ltrim($r['name'] . '.' . $domain, '@.') . '.';

				$preamble[] = $hostname . "\t" . $r['ttl'] . "\tIN\t" .
					$rr . "\t" . $parameter;

				$this->addCache(new Record($domain,
					[
						'name'      => $r['name'],
						'rr'        => $rr,
						'ttl'       => $r['ttl'] ?? static::DNS_TTL,
						'parameter' => $parameter,
						'meta'      => [
							'id' => $r['id']
						]
					]
				));
			}
			$axfrrec = implode("\n", $preamble);
			$this->zoneCache[$domain]['text'] = $axfrrec;
			return $axfrrec;
		}

		/**
		 * Create a Katapult API client
		 *
		 * @return Api
		 */
		private function makeApi(): Api
		{
			return new Api($this->key['token']);
		}

		/**
		 * Get internal Katapult zone ID
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function getZoneId(string $domain): ?string
		{
			return (string)$this->getZoneMeta($domain, 'id');
		}

		/**
		 * Get zone meta information
		 *
		 * @param string $domain
		 * @param string $key
		 * @return mixed|null
		 */
		private function getZoneMeta(string $domain, string $key = null)
		{
			if (!isset($this->metaCache[$domain])) {
				$this->populateZoneMetaCache();
			}
			if (!$key) {
				return $this->metaCache[$domain] ?? null;
			}

			return $this->metaCache[$domain][$key] ?? null;
		}

		/**
		 * Populate zone cache
		 *
		 * @param int $pagenr
		 * @return mixed
		 */
		protected function populateZoneMetaCache($pagenr = 1)
		{
			// @todo support > 100 domains
			$api = $this->makeApi();
			$raw = array_map(static function ($zone) {
				return $zone;
			}, $api->do('GET', 'domains', ['page' => $pagenr]));
			$this->metaCache = array_merge($this->metaCache,
				array_combine(array_column($raw['data'], 'domain'), $raw['data']));
			$pagecnt = $raw['pages'];
			if ($pagenr < $pagecnt && $raw['data']) {
				return $this->populateZoneMetaCache(++$pagenr);
			}
		}

		/**
		 * Get hosting nameservers
		 *
		 * @param string|null $domain
		 * @return array
		 */
		public function get_hosting_nameservers(string $domain = null): array
		{
			return ['ns1.katapult.io', 'ns2.katapult.io'];
		}

		/**
		 * @inheritDoc
		 */
		public function verified(string $domain): bool
		{
			$cache = \Cache_Super_Global::spawn($this->getAuthContext());
			if (true === ($verified = $cache->hGet("dns:katapult.vrfy", $domain))) {
				return $verified;
			}
			$api = $this->makeApi();
			try {
				$status = $api->do('GET', ["dns/zones/_/verification_details?dns_zone[name]=%(domain)s", ['domain' => $domain]]);
			} catch (ClientException $e) {
				$details = $this->renderMessage($e);
				if ($details['code'] === 'dns_zone_already_verified') {
					$cache->hSet("dns:katapult.vrfy", $domain, true);
					return true;
				} else if ($details['code'] === 'dns_zone_not_found') {
					return false;
				}

				return error("DNS verification failed: %s", $details['description']);
			}

			return false;
		}

		/**
		 * @inheritDoc
		 */
		public function challenges(string $domain): array
		{
			$api = $this->makeApi();
			$status = [];
			try {
				$status = $api->do('GET',
					["dns/zones/_/verification_details?dns_zone[name]=%(domain)s", ['domain' => $domain]]);
			} catch (ClientException $e) {
				$details = $this->renderMessage($e);
				if ($details['code'] === 'dns_zone_already_verified') {
					return [];
				}
			}
			return array_filter([
				'ns'  => array_get($status, 'details.nameservers', []),
				'txt' => array_get($status, 'details.txt_record', '')
			]);
		}

		/**
		 * @inheritDoc
		 */
		public function verify(string $domain): bool
		{
			$api = $this->makeApi();
			try {
				$api->do('POST',
					["dns/zones/_/verify?dns_zone[name]=%(domain)s", ['domain' => $domain]]);
			} catch (ClientException $e) {
				return error("Failed to verify `%s': %s", $domain, array_get($this->renderMessage($e), 'description', 'unknown'));
			}
			return true;
		}

		/**
		 * Modify a DNS record
		 *
		 * @param string $zone
		 * @param Record $old
		 * @param Record $new
		 * @return bool
		 */
		protected function atomicUpdate(string $zone, BaseRecord $old, BaseRecord $new): bool
		{
			if (!$this->canonicalizeRecord($zone, $old['name'], $old['rr'], $old['parameter'], $old['ttl'])) {
				return false;
			}
			if (!$this->getRecordId($old)) {
				return error("failed to find record ID in Katapult zone `%s' - does `%s' (rr: `%s', parameter: `%s') exist?",
					$zone, $old['name'], $old['rr'], $old['parameter']);
			}
			if (!$this->canonicalizeRecord($zone, $new['name'], $new['rr'], $new['parameter'], $new['ttl'])) {
				return false;
			}
			$api = $this->makeApi();
			try {
				$merged = clone $old;
				$new = $merged->merge($new);
				$id = $this->getRecordId($old);
				$ret = $api->do('PATCH', "dns/records/${id}", ['details' => $this->formatRecord($new)]);
				$new->setMeta('id', $ret['dns_record']['id']);
			} catch (ClientException $e) {
				return error("Failed to update record `%s' on zone `%s' (old - rr: `%s', param: `%s'; new - rr: `%s', param: `%s'): %s",
					$old['name'],
					$zone,
					$old['rr'],
					$old['parameter'], $new['name'] ?? $old['name'], $new['parameter'] ?? $old['parameter'],
					array_get($this->renderMessage($e), 'description', 'unknown')
				);
			}
			array_forget($this->zoneCache[$old->getZone()], $this->getCacheKey($old));
			$this->addCache($new);

			return true;
		}

		/**
		 * Format a Katapult record prior to sending
		 *
		 * @param Record $r
		 * @return array
		 */
		protected function formatRecord(Record $r): ?array
		{
			$args = [
				'name'        => $r['name'],
				'ttl'         => $r['ttl'] ?? static::DNS_TTL,
				'record_type' => strtolower($r['rr']),
			];
			return $args + ['properties' => $this->formatRecordProperties($r)];
		}

		private function formatRecordProperties(Record $r): array
		{
			switch (strtoupper($r['rr'])) {
				case 'A':
				case 'AAAA':
					return ['ip' => $r['parameter']];
				case 'CNAME':
				case 'NS':
					return ['name' => $r['parameter']];
				case 'TXT':
					return ['data' => $r['parameter']];
				case 'MX':
					return [
						'priority' => $r->getMeta('priority'),
						'host'     => $r->getMeta('data')
					];
				case 'SRV':
					return [
						'target'   => $r->getMeta('data'),
						'priority' => $r->getMeta('priority'),
						'weight'   => $r->getMeta('weight'),
						'port'     => $r->getMeta('port'),
					];
				case 'SSHFP':
					return [
						'algorithm'        => $r->getMeta('algorithm'),
						'fingerprint_type' => $r->getMeta('type'),
						'fingerprint'      => $r->getMeta('data')
					];
				case 'CAA':
					return [
						'flags'          => $r->getMeta('flags'),
						'property_type'  => $r->getMeta('tag'),
						// doesn't support flags usage
						'property_value' => trim($r->getMeta('data'), '"')
					];
				default:
					fatal("Unsupported DNS RR type `%s'", $r['type']);
			}

			return [];
		}

		/**
		 * Extract JSON message if present
		 *
		 * @param ClientException $e
		 * @return string
		 */
		private function renderMessage(ClientException $e): array
		{

			$body = \Error_Reporter::silence(static function () use ($e) {
				return \json_decode($e->getResponse()->getBody()->getContents(), true);
			});
			if (!$body || !($reason = array_get($body, 'error'))) {
				return ['description' => $e->getMessage(), 'code' => 'unknown'];
			}

			return $reason;
		}

		/**
		 * CNAME cannot be present in root
		 *
		 * @return bool
		 */
		protected function hasCnameApexRestriction(): bool
		{
			return false;
		}
	}
