<?php
/**
 * Yandex PHP Library
 *
 * @copyright NIX Solutions Ltd.
 * @link https://github.com/nixsolutions/yandex-php-library
 */

/**
 * @namespace
 */

namespace Yandex\OAuth;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\RequestException;
use Yandex\Common\AbstractServiceClient;
use Yandex\OAuth\Exception\AuthRequestException;
use Yandex\OAuth\Exception\AuthResponseException;

/**
 * Class OAuthClient implements Yandex OAuth protocol
 *
 * @category Yandex
 * @package  OAuth
 *
 * @author   Eugene Zabolotniy <realbaziak@gmail.com>
 * @created  29.08.13 12:07
 */
class OAuthClient extends AbstractServiceClient
{
    /*
     * Authentication types constants
     *
     * The "code" type means that the application will use an intermediate code to obtain an access token.
     * The "token" type will result a user is redirected back to the application with an access token in a URL
     */
    const CODE_AUTH_TYPE = 'code';
    const TOKEN_AUTH_TYPE = 'token';
    /**
     * @var string
     */
    protected $serviceDomain = 'oauth.yandex.ru';
    /**
     * @var string
     */
    private $clientId = '';
    /**
     * @var string
     */
    private $clientSecret = '';

    /**
     * @var string
     */
    protected $tokenType;

    /**
     * @var string
     */
    protected $refreshToken;

    /**
     * @param string $clientId
     * @param string $clientSecret
     */
    public function __construct($clientId = '', $clientSecret = '')
    {
        $this->setClientId($clientId);
        $this->setClientSecret($clientSecret);
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @param string $clientId
     *
     * @return self
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;

        return $this;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @param string $clientSecret
     *
     * @return self
     */
    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;

        return $this;
    }

    /**
     * @param string $tokenType
     * @return self
     */
    public function setTokenType($tokenType)
    {
        $this->tokenType = $tokenType;

        return $this;
    }

    /**
     * @param  string $refreshToken
     * @return self
     */
    public function setRefreshToken($refreshToken)
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }

    /**
     * Return object of Client without auth headers
     * @return Client
     */
    public function setDefaultClient()
    {
        $defaultOptions = [
            'base_uri' => $this->getServiceUrl(),
            'headers' => [
                'Host' => $this->getServiceDomain(),
                'User-Agent' => $this->getUserAgent(),
                'Accept' => '*/*',
            ],
        ];

        return new Client($defaultOptions);
    }

    /**
     * Build url with query params
     *
     * @param array $queryData
     * @param string $prefix
     * @param string $argSeparator
     * @param int $encType
     * @return mixed|string
     */
    protected function buildQueryString(
        array $queryData,
        $prefix = '',
        $argSeparator = '&',
        $encType = PHP_QUERY_RFC3986
    ) {
        foreach ($queryData as $key => &$value) {
            if (!is_scalar($value)) {
                $value = implode(',', $value);
            }
        }

        $queryString = http_build_query($queryData, $prefix, $argSeparator, $encType);

        foreach ($queryData as $key => $value) {
            if ($key === $value) {
                $queryString = str_replace("{$key}={$value}", $value, $queryString);
            }
        }

        return $queryString;
    }

    /**
     * @param array $result
     * @return self
     * @throws \Exception
     */
    public function setTokenData($result)
    {
        if (!isset($result['access_token'])) {
            throw new AuthResponseException('Server response doesn\'t contain access token');
        }
        $this->setAccessToken($result['access_token']);
        $lifetimeInSeconds = $result['expires_in'];
        $this->setRefreshToken($result['refresh_token']);
        $this->setTokenType($result['token_type']);
        $expireDateTime = new \DateTime();
        $expireDateTime->add(new \DateInterval('PT' . $lifetimeInSeconds . 'S'));
        $this->setExpiresIn($expireDateTime);

        return $this;
    }
    /**
     * @param $response
     * @return mixed|\SimpleXMLElement
     * @throws AuthResponseException
     */
    public function decodeResponse($response)
    {
        try {
            $result = $this->getDecodedBody($response->getBody());
        } catch (\RuntimeException $ex) {
            throw new AuthResponseException('Server response can\'t be parsed', 0, $ex);
        }

        if (!is_array($result)) {
            throw new AuthResponseException('Server response has unknown format');
        }

        return $result;
    }

    /**
     * @param $result
     * @param $ex
     * @throws AuthRequestException
     */
    public function decodeErrorResponse($result, $ex)
    {
        if (is_array($result) && isset($result['error'])) {
            // handle a service error message
            $message = 'Service recponsed with error code "' . $result['error'] . '".';

            if (isset($result['error_description']) && $result['error_description']) {
                $message .= ' Description "' . $result['error_description'] . '".';
            }
            throw new AuthRequestException($message, 0, $ex);
        }
        // unknown error. not parsed error
        throw $ex;
    }

    /**
     * Sends a redirect to the Yandex authentication page.
     *
     * @param bool $exit indicates whether to stop the PHP script immediately or not
     * @param string $type a type of the authentication procedure
     * @param string $state optional string
     *
     * @param array $params
     * @return bool|void
     */
    public function authRedirect($exit = true, $type = self::CODE_AUTH_TYPE, $state = null, array $params = [])
    {
        header('Location: ' . $this->getAuthUrl($type, $state, $params));

        return $exit ? exit() : true;
    }

    /**
     * @param string $type
     * @param string $state optional string
     *
     * @param array $params
     * @return string
     */
    public function getAuthUrl($type = self::CODE_AUTH_TYPE, $state = null, array $params = [])
    {
        $url = $this->getServiceUrl('authorize') . '?response_type=' . $type . '&client_id=' . $this->clientId;
        $url .= '&' . $this->buildQueryString($params);
        if ($state) {
            $url .= '&state=' . $state;
        }

        return $url;
    }

    /**
     * Exchanges a temporary code for an access token.
     *
     * @param $code
     *
     * @return self
     * @throws AuthResponseException on a response format error
     * @throws RequestException on an unknown request error*@throws \GuzzleHttp\Exception\GuzzleException
     *
     * @throws AuthRequestException on a known request error
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Exception
     */
    public function requestAccessToken($code, array $params = [])
    {
        $client = $this->getClient();
        $formParams = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];
        $formParams = array_merge($formParams, $params);

        try {
            $response = $client->request(
                'POST',
                '/token',
                [
                    'auth' => [
                        $this->clientId,
                        $this->clientSecret,
                    ],
                    'form_params' => $formParams,
                ]
            );
        } catch (ClientException $ex) {
            $result = $this->getDecodedBody($ex->getResponse()->getBody());

            $this->decodeErrorResponse($result, $ex);
        }

        try {
            $result = $this->decodeResponse($response);
        } catch (AuthResponseException $e) {
            throw new AuthRequestException($e);
        }

        return $this->setTokenData($result);
    }

    /**
     * Get device id for get token
     *
     * @param array $params
     * @return $this
     * @throws AuthRequestException
     * @throws AuthResponseException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getDeviceIdByYandexOAuth(array $params = [])
    {
        $client = $this->setDefaultClient();
        $formParams = [
            'client_id' => $this->clientId,
        ];
        $formParams = array_merge($formParams, $params);
        try {
            $response = $client->request(
                'POST',
                '/device/code',
                [
                    'form_params' => $formParams,
                ]
            );
        } catch (ClientException $ex) {
            $result = $this->getDecodedBody($ex->getResponse()->getBody());

            $this->decodeErrorResponse($result, $ex);
        }
        try {
            $result = $this->decodeResponse($response);
        } catch (AuthResponseException $e) {
            throw new AuthRequestException($e);
        }

        $response = [
            'device_code' => $result['device_code'],
            'user_code' => $result['user_code'],
            'interval' => $result['interval'],
            'expires_in' => $result['expires_in'],
            'verification_url' => $result['verification_url']
        ];

        return $response;
    }

    /**
     * Get token by device id
     *
     * @param $deviceCode
     * @param array $params
     * @return $this
     * @throws AuthRequestException
     * @throws AuthResponseException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAccessTokenByYandexOAuth($deviceCode, array $params = [])
    {
        $client = $this->setDefaultClient();
        try {
            $response = $client->request(
                'POST',
                '/token',
                [
                    'form_params' => [
                        'grant_type' => 'device_code',
                        'code' => $deviceCode,
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                    ]
                ]
            );
        } catch (ClientException $ex) {
            $result = $this->getDecodedBody($ex->getResponse()->getBody());
            $this->decodeErrorResponse($result, $ex);
        }

        try {
            $result = $this->decodeResponse($response);
        } catch (AuthResponseException $e) {
            throw new AuthRequestException($e);
        }

        return $this->setTokenData($result);
    }

    /**
     * Get token with refresh token
     *
     * @param $refreshToken
     * @return $this
     * @throws AuthRequestException
     * @throws AuthResponseException
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Exception
     */
    public function refreshToken($refreshToken)
    {
        $client = $this->setDefaultClient();
        try {
            $response = $client->request(
                'POST',
                '/token',
                [
                    'form_params' => [
                        'grant_type' => 'refresh_token',
                        'refresh_token' => $refreshToken,
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                    ]
                ]
            );
        } catch (ClientException $ex) {
            $result = $this->getDecodedBody($ex->getResponse()->getBody());
            $this->decodeErrorResponse($result, $ex);
        }
        try {
            $result = $this->decodeResponse($response);
        } catch (AuthResponseException $e) {
            throw new AuthRequestException($e);
        }

        return $this->setTokenData($result);
    }
}