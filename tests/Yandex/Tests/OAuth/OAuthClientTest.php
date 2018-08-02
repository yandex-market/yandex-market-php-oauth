<?php

namespace Yandex\Tests\OAuth;

use GuzzleHttp\Client as GuzzleHttpClient;
use GuzzleHttp\Exception\ClientException as GuzzleHttpClientException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Yandex\OAuth\Exception\AuthRequestException;
use Yandex\OAuth\Exception\AuthResponseException;
use Yandex\OAuth\OAuthClient;
use Yandex\Tests\TestCase;

class OAuthClientTest extends TestCase
{
    public function testGetClient()
    {
        $oauthClient = $this->getOauthClient();

        $getClient = self::getNotAccessibleMethod($oauthClient, 'getClient');

        $guzzleClient = $getClient->invokeArgs($oauthClient, []);

        $this->assertInstanceOf('\GuzzleHttp\ClientInterface', $guzzleClient);
    }

    /**
     * @param string $clientId
     *
     * @return OAuthClient
     */
    private function getOauthClient($clientId = 'test')
    {
        return new OAuthClient($clientId);
    }

    /**
     * @param $accessToken
     * @param $expectedAccessToken
     *
     * @dataProvider dataSetGetAccessToken
     */
    public function testSetGetAccessToken($accessToken, $expectedAccessToken)
    {
        $oauthClient = $this->getOauthClient();

        $this->assertEmpty($oauthClient->getAccessToken());

        $oauthClient->setAccessToken($accessToken);

        $this->assertEquals($expectedAccessToken, $oauthClient->getAccessToken());
    }

    /**
     * @return array
     */
    public function dataSetGetAccessToken()
    {
        return [
            'empty access token' => [
                'accessToken' => null,
                'expectedAccessToken' => null,
            ],
            'not empty access token' => [
                'accessToken' => 'test',
                'expectedAccessToken' => 'test',
            ],
        ];
    }

    /**
     * @param $accessToken
     * @param $expectedAccessToken
     *
     * @dataProvider dataSetGetAccessToken
     */
    public function testSetGetExpiresIn($expiresIn, $expectedExpiresIn)
    {
        $oauthClient = $this->getOauthClient();

        $this->assertEmpty($oauthClient->getExpiresIn());

        $oauthClient->setExpiresIn($expiresIn);

        $this->assertEquals($expectedExpiresIn, $oauthClient->getExpiresIn());
    }

    /**
     * @return array
     */
    public function dataSetGetExpiresIn()
    {
        return [
            'empty expires_in' => [
                'expiresIn' => null,
                'expectedExpiresIn' => null,
            ],
            'not empty expires_in' => [
                'expiresIn' => new \DateTime('2020-01-01 00:00:00'),
                'expectedExpiresIn' => new \DateTime('2020-01-01 00:00:00'),
            ],
        ];
    }

    /**
     * @param $clientId
     * @param $expectedClientId
     *
     * @dataProvider dataSetGetClientId
     */
    public function testSetGetClientId($clientId, $expectedClientId)
    {
        $oauthClient = $this->getOauthClient();
        $oauthClient->setClientId($clientId);
        $this->assertEquals($expectedClientId, $oauthClient->getClientId());
    }

    /**
     * @return array
     */
    public function dataSetGetClientId()
    {
        return [
            'empty client id' => [
                'clientId' => null,
                'expectedClientId' => null,
            ],
            'not empty client id' => [
                'clientId' => 'test',
                'expectedClientId' => 'test',
            ],
        ];
    }

    /**
     * @param $clientSecret
     * @param $expectedClientSecret
     *
     * @dataProvider dataSetGetClientSecret
     */
    public function testSetGetClientSecret($clientSecret, $expectedClientSecret)
    {
        $oauthClient = $this->getOauthClient();
        $oauthClient->setClientSecret($clientSecret);
        $this->assertEquals($expectedClientSecret, $oauthClient->getClientSecret());
    }

    /**
     * @return array
     */
    public function dataSetGetClientSecret()
    {
        return [
            'empty client secret' => [
                'clientSecret' => null,
                'expectedClientSecret' => null,
            ],
            'not empty client secret' => [
                'clientSecret' => 'test',
                'expectedClientSecret' => 'test',
            ],
        ];
    }

    /**
     * @param $serviceDomain
     * @param $expectedServiceDomain
     *
     * @dataProvider dataSetGetServiceDomain
     */
    public function testSetGetServiceDomain($serviceDomain, $expectedServiceDomain)
    {
        $oauthClient = $this->getOauthClient();

        $this->assertNotEmpty($oauthClient->getServiceDomain());

        $oauthClient->setServiceDomain($serviceDomain);

        $this->assertEquals($expectedServiceDomain, $oauthClient->getServiceDomain());
    }

    /**
     * @return array
     */
    public function dataSetGetServiceDomain()
    {
        return [
            'empty service domain' => [
                'serviceDomain' => null,
                'expectedServiceDomain' => null,
            ],
            'not empty service domain' => [
                'serviceDomain' => 'test',
                'expectedServiceDomain' => 'test',
            ],
        ];
    }

    /**
     * @param $servicePort
     * @param $expectedServicePort
     *
     * @dataProvider dataSetGetServicePort
     */
    public function testSetGetServicePort($servicePort, $expectedServicePort)
    {
        $oauthClient = $this->getOauthClient();

        $this->assertEmpty($oauthClient->getServicePort());

        $oauthClient->setServicePort($servicePort);

        $this->assertEquals($expectedServicePort, $oauthClient->getServicePort());
    }

    /**
     * @return array
     */
    public function dataSetGetServicePort()
    {
        return [
            'empty service port' => [
                'servicePort' => null,
                'expectedServicePort' => null,
            ],
            'not empty service port' => [
                'servicePort' => 'test',
                'expectedServicePort' => 'test',
            ],
        ];
    }

    /**
     * @param $serviceScheme
     * @param $expectedServiceScheme
     *
     * @dataProvider dataSetGetServiceScheme
     */
    public function testSetGetServiceScheme($serviceScheme, $expectedServiceScheme)
    {
        $oauthClient = $this->getOauthClient();

        $this->assertNotEmpty($oauthClient->getServiceScheme());

        $oauthClient->setServiceScheme($serviceScheme);

        $this->assertEquals($expectedServiceScheme, $oauthClient->getServiceScheme());
    }

    /**
     * @param $resource
     * @param $expectedServiceUrl
     *
     * @dataProvider dataGetServiceUrl
     */
    public function testGetServiceUrl($resource, $expectedServiceUrl)
    {
        $oauthClient = $this->getOauthClient();

        $this->assertEquals($expectedServiceUrl, $oauthClient->getServiceUrl($resource));
    }

    /**
     * @return array
     */
    public function dataGetServiceUrl()
    {
        return [
            'empty service resource' => [
                'resource' => null,
                'expectedServiceUrl' => 'https://oauth.yandex.ru/',
            ],
            'not empty service resource' => [
                'resource' => 'test',
                'expectedServiceUrl' => 'https://oauth.yandex.ru/test',
            ],
        ];
    }

    /**
     * @return array
     */
    public function dataSetGetServiceScheme()
    {
        return [
            'empty service scheme' => [
                'serviceScheme' => null,
                'expectedServiceScheme' => null,
            ],
            'not empty service scheme' => [
                'serviceScheme' => 'test',
                'expectedServiceScheme' => 'test',
            ],
        ];
    }

    public function testGetAuthUrl()
    {
        $oauthClient = $this->getOauthClient();
        $url = $oauthClient->getAuthUrl(OAuthClient::CODE_AUTH_TYPE, 'state');
        $this->assertTrue(strpos($url, 'state') > 0);
    }

    /**
     * @runInSeparateProcess
     */
    public function testAuthRedirect()
    {
        $oauthClient = $this->getOauthClient();
        $this->assertTrue($oauthClient->authRedirect(false));
    }

    public function testRequestAccessToken()
    {
        $code = '33333333';
        $clientId = 'client-id';
        $clientSecret = 'client-secret';

        $response = new Response(
            200,
            [
                'Content-type' => 'application/json',
            ],
            json_encode([
                "access_token" => "5fd980a5133b4887a8937fe07d3a0a60",
                "token_type" => "bearer",
                "expires_in" => 124234123534,
            ]),
            '1.1',
            'OK'
        );

        $guzzleClient = $this->getMockBuilder(GuzzleHttpClient::class)
            ->setMethods(['request'])
            ->getMock();

        $guzzleClient->expects($this->once())
            ->method('request')
            ->with(
                $this->equalTo('POST'),
                $this->equalTo('/token'),
                $this->equalTo([
                    'auth' => [
                        $clientId,
                        $clientSecret,
                    ],
                    'form_params' => [
                        'grant_type' => 'authorization_code',
                        'code' => $code,
                        'client_id' => $clientId,
                        'client_secret' => $clientSecret,
                    ],
                ])
            )
            ->willReturn($response);

        $oauthClient = $this->getOauthClient();

        $setClient = self::getNotAccessibleMethod($oauthClient, 'setClient');

        $setClient->invokeArgs($oauthClient, [$guzzleClient]);

        $oauthClient->setClientId($clientId);
        $oauthClient->setClientSecret($clientSecret);

        $oauthClient->requestAccessToken($code);
    }

    public function testRequestAuthRequestException()
    {
        $code = '33333333';
        $json = '{"error_description": "Invalid code", "error": "bad_verification_code"}';
        $response = new Response(400, [], \GuzzleHttp\Psr7\stream_for($json));
        $request = new Request('POST', '');
        $exception = new \GuzzleHttp\Exception\ClientException('error', $request, $response);
        $guzzleHttpClientMock = $this->getMockBuilder(GuzzleHttpClient::class)
            ->setMethods(['request'])
            ->getMock();
        $guzzleHttpClientMock->expects($this->any())
            ->method('request')
            ->will($this->throwException($exception));
        $oauthClientMock = $this->getMockBuilder(OAuthClient::class)
            ->setMethods(['getClient'])
            ->getMock();
        $oauthClientMock->expects($this->any())
            ->method('getClient')
            ->will($this->returnValue($guzzleHttpClientMock));

        $this->expectException(AuthRequestException::class);
        $oauthClientMock->requestAccessToken($code);
    }

    public function testRequestEmptyResponseAndException()
    {
        $code = '33333333';
        $response = new Response(400, [], \GuzzleHttp\Psr7\stream_for(''));
        $request = new Request('POST', '');
        $exception = new \GuzzleHttp\Exception\ClientException('error', $request, $response);
        $guzzleHttpClientMock = $this->getMockBuilder(GuzzleHttpClient::class)
            ->setMethods(['request'])
            ->getMock();
        $guzzleHttpClientMock->expects($this->any())
            ->method('request')
            ->will($this->throwException($exception));
        $oauthClientMock = $this->getMockBuilder(OAuthClient::class)
            ->setMethods(['getClient'])
            ->getMock();
        $oauthClientMock->expects($this->any())
            ->method('getClient')
            ->will($this->returnValue($guzzleHttpClientMock));

        $this->expectException(GuzzleHttpClientException::class);
        $oauthClientMock->requestAccessToken($code);
    }

    public function testRequestEmptyResponseAuthResponseException()
    {
        $code = '33333333';
        $response = new Response(200, [], \GuzzleHttp\Psr7\stream_for(''));
        $guzzleHttpClientMock = $this->getMockBuilder(GuzzleHttpClient::class)
            ->setMethods(['request'])
            ->getMock();
        $guzzleHttpClientMock->expects($this->any())
            ->method('request')
            ->will($this->returnValue($response));
        $oauthClientMock = $this->getMockBuilder(OAuthClient::class)
            ->setMethods(['getClient'])
            ->getMock();
        $oauthClientMock->expects($this->any())
            ->method('getClient')
            ->will($this->returnValue($guzzleHttpClientMock));

        $this->expectException(AuthResponseException::class);
        $oauthClientMock->requestAccessToken($code);
    }

    public function testRequestAccessTokenResponseWithoutToken()
    {
        $code = '33333333';
        $json = '{"error_description": "Invalid code", "error": "bad_verification_code"}';
        $response = new Response(400, [], \GuzzleHttp\Psr7\stream_for($json));
        $guzzleHttpClientMock = $this->getMockBuilder(GuzzleHttpClient::class)
            ->setMethods(['request'])
            ->getMock();
        $guzzleHttpClientMock->expects($this->any())
            ->method('request')
            ->will($this->returnValue($response));
        $oauthClientMock = $this->getMockBuilder(OAuthClient::class)
            ->setMethods(['getClient'])
            ->getMock();
        $oauthClientMock->expects($this->any())
            ->method('getClient')
            ->will($this->returnValue($guzzleHttpClientMock));

        $this->expectException(AuthResponseException::class);
        $oauthClientMock->requestAccessToken($code);
    }

    public function testRequestAccessTokenResponseInvalidJson()
    {
        $code = '33333333';
        $exception = new \RuntimeException('error');
        $guzzleResponseMock = $this->getMockBuilder(Response::class)
            ->setMethods(['getBody'])
            ->getMock();
        $guzzleResponseMock->expects($this->any())
            ->method('getBody')
            ->will($this->throwException($exception));

        $guzzleHttpClientMock = $this->getMockBuilder(GuzzleHttpClient::class)
            ->setMethods(['request'])
            ->getMock();
        $guzzleHttpClientMock->expects($this->any())
            ->method('request')
            ->will($this->returnValue($guzzleResponseMock));
        $oauthClientMock = $this->getMockBuilder(OAuthClient::class)
            ->setMethods(['getClient'])
            ->getMock();
        $oauthClientMock->expects($this->any())
            ->method('getClient')
            ->will($this->returnValue($guzzleHttpClientMock));

        $this->expectException(AuthResponseException::class);
        $oauthClientMock->requestAccessToken($code);
    }
}
