<?php declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, July 2020
	 */

	namespace Opcenter\Dns\Providers\Katapult;

	use GuzzleHttp\Exception\RequestException;
	use Opcenter\Dns\Contracts\ServiceProvider;
	use Opcenter\Service\ConfigurationContext;

	class Validator implements ServiceProvider
	{
		public function valid(ConfigurationContext $ctx, &$var): bool
		{
			if (!is_array($var)) {
				return $this->validateKey($var);
			}

			if (!isset($var['token'])) {
				return error("'token' field must be present in complex field");
			}

			return $this->validateKey((string)$var['token']) && !array_diff_key($var, ['token' => 0, 'org' => 0]);
		}

		private function validateKey(string $key): bool
		{
			return strlen($key) >= 32 && static::keyValid($key);
		}

		public static function keyValid(string $key): bool
		{
			try {
				(new Api($key))->do('GET', 'data_centers');
			} catch (RequestException $e) {
				$reason = $e->getMessage();
				if (null !== ($response = $e->getResponse())) {
					$response = \json_decode($response->getBody()->getContents(), true);
					$reason = array_get($response, 'error.description', 'Invalid key');
				}

				return error('%(provider)s key validation failed: %(reason)s', [
					'provider' => 'Katapult',
					'reason'   => $reason
				]);
			}

			return true;
		}
	}
