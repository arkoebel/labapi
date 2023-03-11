<?php

require_once __DIR__ . '/vendor/autoload.php';

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Checker;
use Jose\Component\KeyManagement\Analyzer\KeyIdentifierAnalyzer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSBuilder;

class Server2Jwt
{

    public static function verifySignature($incomingJwt, $location = '.')
    {
        $config = json_decode(file_get_contents($location . '/server-to-jwt.config.json'), true);
        $keys = $config['clientCerts'];
        //error_log('keys : ' . print_r($keys,true));
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);

        try{

            $jws = $serializerManager->unserialize($incomingJwt);
            //error_log('jwt=' . print_r($jws,true));
        }catch(Exception $e){
            error_log('oops: ' . $e->getMessage());
            throw new InvalidArgumentException('Bad JWT Format ' . $e->getMessage());
        }
        $headerCheckerManager = new HeaderCheckerManager(
            [
                new AlgorithmChecker(['RS256'])
            ],
            [
                new JWSTokenSupport(), // Adds JWS token type support
            ]
        );

        $claimCheckerManager = new ClaimCheckerManager(
            [
                new Checker\IssuerChecker([$config['clientAppCN']])
            ]
        );

        $headerCheckerManager->check($jws, 0, ['alg', 'typ', 'kid']);

        $claims = json_decode($jws->getPayload(), true);
        $claimCheckerManager->check($claims, ['iss', 'etp', 'iat']);

        $kid = $jws->getSignature(0)->getProtectedHeader()['kid'];
        //error_log('Key Fingerprint: ' . $kid . "\n");
        //error_log('Key: ' . $keys[$kid] . "\n");
        if (!array_key_exists($kid, $keys))
            throw new InvalidArgumentException("Key Identifier Unknown");

        $jwk = JWKFactory::createFromKey($keys[$kid], null, array('kty' => 'RSA'));

        $algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);

        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );
        if (!$jwsVerifier->verifyWithKey($jws, $jwk, 0))
            throw new InvalidArgumentException('Invalid signature');

        return $jws->getPayload();
    }

    public static function envelopSignature($payload)
    {
        $config = json_decode(file_get_contents('server-to-jwt.config.json'), true);
        unset($payload['iat']);
        $data = json_encode(
            array_merge_recursive(
                array(
                    "etp" => array(
                        "type" => "INTERNAL",
                        "tlv" => "PRIVATE",
                        "consumerName" => $payload['iss']
                    ),
                    "ver" => "2.0",
                    "codeacces" => "12345",
                    "iss" => "Arkea",
                    "noPerson" => "54321",
                    "aud" => "ARKEA",
                    "efs" => $payload['etp']['efs'],
                    "accescode" => "12345",
                    "orig" => array(
                        "src" => "EXTERNAL_" . $payload['iss']
                    ),
                    "si" => $payload['etp']['si'],
                    "accessCode" => "12345",
                    "exp" => time() + intval($config['tokenExpiration']),
                    "iat" => time(),
                    "jti" => "f62a02cb-17a7-49d5-84d1-7af138d9095e",
                    "cypherkey" => "1a5e3fd22eaf8f88"

                ),
                $payload
            )
        );

        $algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);
        $key = $config['serverKey'];
        $jwk = JWKFactory::createFromKey($key, null, array('kty' => 'RSA'));

        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jws = $jwsBuilder
            ->create()                                  // We want to create a new JWS
            ->withPayload($data)                        // We set the payload
            ->addSignature($jwk, ['alg' => 'RS256', 'typ' => 'JWT'])    // We add a signature with a simple protected header
            ->build();

        $serializer = new CompactSerializer(); // The serializer

        return array('jwt' => $serializer->serialize($jws, 0), 'payload' => $data);
    }
}
