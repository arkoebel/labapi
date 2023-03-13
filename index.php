<?php
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/Server2Jwt.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Silex\Application;
use Swagger\Server\Model\ControlResponse;

use Swagger\Server\ObjectSerializer;
use JsonPath\JsonObject;

$app = new Silex\Application();


function objEq(stdClass $obj1, stdClass $obj2): bool
{
    //   error_log('new object call');
    $a1 = (array)$obj1;
    $a2 = (array)$obj2;
    return arrEq($a1, $a2);
}

function arrEq(array $a1, array $a2): bool
{
    //    error_log('new call');
    foreach ($a1 as $k => $v) {
        //        error_log('key: ' . $k);
        if (array_key_exists($k, $a2)) {
            if ($v instanceof stdClass) {
                $r = objEq($v, $a2[$k]);

                //error_log(print_r($v,true));
                //error_log(print_r($a2[$k],true));
                if ($r === false) {
                    error_log('different objects : ' . print_r($v, true) . ' vs ' . print_r($a2[$k], true));
                    return false;
                }
            } else if (is_array($v)) {
                $r = arrEq($v, $a2[$k]);

                if ($r === false) {
                    error_log('different arrays : ' . print_r($v, true) . ' vs ' . print_r($a2[$k], true));
                    return false;
                }
            } else if (is_double($v)) {
                // required to avoid rounding errors due to the 
                // conversion from string representation to double
                if (abs($v - $a2[$k]) > 0.000000000001) {
                    error_log('different values for ' . $k . ' : ' . $v . '/' . $a2[$k]);
                    return false;
                }
            } else {
                if ($v != $a2[$k]) {
                    error_log('different values for ' . $k . ' : ' . $v . '/' . $a2[$k]);
                    return false;
                }
            }
        } else {
            error_log('key doesnt exist : ' . $k);
            return false;
        }
    }
    //error_log('return ok');
    return true;
}

function validateHeader($auth, &$response, &$auth_params)
{
    if (preg_match('/Bearer (.*)/', $auth, $matches)) {
        error_log('Auth JWT : ' . $matches[1]);
        $jwt = $matches[1];
        try {
            $auth_params = Server2Jwt::verifySignature($jwt,'.','client');
            $auth_params = json_decode($auth_params, true);
            error_log('Decoded JWT = ' . print_r($auth_params, true));
            error_log('Verified JWT Token OK');
            return true;
        } catch (Exception $e) {
            error_log('Bad Token : ' . $e->getMessage());
            error_log($e->getTraceAsString());
            $response = new Response('Bad Token ' . $e->getMessage(), 401);
            return false;
        }
    } else {
        error_log('Missing Auth');
        $response = new Response('Not Authorized', 401);
        return false;
    }
}

function getResp($config, $json, $type)
{
    $jobj = new JsonObject($json,true);
    foreach ($config[$type] as $match) {
        $mm = true;
        error_log('Testing ' . $match['comment'] . "\n");
        foreach ($match['elements'] as $element) {
            $val = $jobj->get($element['jsonPath']);
            
            if ($val === null)
                break;
            if ('EQUALS' === $element['operator']) {
                if ($val[0] === $element['value']){
                    
                    error_log('JSONPath OK: ' . $element['jsonPath'] . ' = ' . $val[0] . "\n");
                }else{
                    $mm = false;
                    error_log('JSONPath FAIL: ' . $element['jsonPath'] . ' != ' . $val[0] . "\n");
                    break;
                }
            } else if ('CONTAINS' === $element['operator']) {
                if (!(strstr($val[0], $element['value']) === false)){
                    error_log('JSONPath OK: ' . $element['jsonPath'] . ' includes ' . $val[0] . "\n");
                }else{
                    $mm = false;
                    error_log('JSONPath FAIL: ' . $element['jsonPath'] . ' doesnt include ' . $val[0] . "\n");
                    break;
                }
            } else if('EXISTS' === $element['operator']){
                if((count($val) != 0)){
                    error_log('JSONPath OK: ' . $element['jsonPath'] . ' Exists' . "\n");
                }else{
                    $mm = false;
                    error_log('JSONPath FAIL: ' . $element['jsonPath'] . ' doesnt exist' . "\n");
                    break;
                }
            }
        }
        if ($mm)
            return $match;
    }
    return null;
}

function buildResponse($resp, $jsonIn, &$jsonOut)
{
    $jst = new JsonObject($jsonOut,true);
    $jstin = new JsonObject($jsonIn,true);
    $rr = 200;

    error_log('json in =' . (string) $jstin);
   
    foreach ($resp as $ob) {
        if (array_key_exists('destJsonPath', $ob)) {
            if (array_key_exists('value', $ob)){
                if(array_key_exists('type',$ob)&&($ob['type']=='JSON')){
                    $val = json_decode(json_encode($ob['value']),true);
                    //$val = $ob['value'];
                }else
                    $val = $ob['value'];
                $jst->set($ob['destJsonPath'], $val);
                error_log('Replace ' . $ob['destJsonPath'] . ' with ' . json_encode($val));
                //error_log('json=' . (string) $jst);
            }else if (array_key_exists('srcJsonPath', $ob)){
                $zz = $jstin->get($ob['srcJsonPath']);
                //error_log('zz=' . print_r($zz,true));
                if (is_array($zz))
                    $jst->set($ob['destJsonPath'],(string) $zz[0]);
                else
                    $jst->set($ob['destJsonPath'],$zz);
                error_log('src=' . print_r($jstin->get($ob['srcJsonPath']),true));
                error_log('Replace ' . $ob['destJsonPath'] . ' with ' . $ob['srcJsonPath']);
                //error_log('json=' . print_r($jst, true));
            }
        } else if (array_key_exists('status', $ob)) {
            $rr = $ob['status'];
            if (array_key_exists('output',$ob)){
                $jsonOut = $ob['output'];
                return $rr;
            }
        }
    }
    $jsonOut = (string) $jst;
    return $rr;
}

function getAPIResponse($request,$dataType,$matchType){
    $config = json_decode(file_get_contents('labapi.config.json'), true);
    if ($config===null)
        return new Response('Invalid configuration',500);
    $jwt = '';
    $resp = '';
    if (!validateHeader($request->headers->get('Authorization'), $resp, $jwt))
        return new Response('Invalid JWT',403);

    $input = $request->getContent();
    $json = json_decode($input);

    if(!is_countable($json))
        return new Response('Invalid Input (empty JSON)', 400);

    if (count($json) == 0)
        return new Response('Invalid Input (not JSON)', 400);

    $map = array();
    foreach ($json as $element)
        $map[] = ObjectSerializer::deserialize($element, $dataType);
    $res = ObjectSerializer::sanitizeForSerialization($map);

    if (!(arrEq($json, (Array) $res)))
        return new Response('Invalid Input (invalid format)', 400);

    $response = new ControlResponse(array(
        'efs_code' => $jwt['etp']['efs'],
        'external_direct_debit_id' => $map[0]->getExternalDirectDebitId(),
        'messages' => array("code"=>"0","field"=>"aa", "message"=>"bb"),
        'status' => 'OK'
    ));
    $rr = json_decode(json_encode(ObjectSerializer::sanitizeForSerialization($response)),true);
    $jinput = json_decode($input,true);
    $section = getResp($config, $jinput, $matchType);
    $ra = 0;
    if (!($section === null)){
        error_log('Selected section : ' . $section['comment'] . "\n");
        
        $ra = buildResponse($section['response'],$jinput, $rr);
        $outr = $rr; //json_encode($rr);
    }else{
        error_log("Default response: not found\n");
        $outr = "Default response: not found\n";
        $ra = 404;
    }
    return new Response($outr,$ra);
}

$app->POST('/labapi/api/v1/directDebits/internal/control', function (Application $app, Request $request) {
    return getAPIResponse($request,'Swagger\Server\Model\InternalDirectDebit', 'directDebitMatches');
});


$app->POST('/labapi/api/v1/transfers/internal/control', function (Application $app, Request $request) {
    return getAPIResponse($request,'Swagger\Server\Model\InternalTransfer', 'transferMatches');
});


$app->POST('/server-to-jwt/jwt', function (Application $app, Request $request) {
    try {
        error_log('Got JWT Token request');
        $payload = Server2Jwt::verifySignature($request->getContent());

        error_log('Validated JWT Token');
        $token = Server2Jwt::envelopSignature(json_decode($payload, true));

        error_log('Generated JWT Token');

        $response = new Response($token['payload'], 200, array('Authorization' => ' Bearer ' . $token['jwt']));
    } catch (Exception $e) {
        error_log('Got error : ' . $e->getMessage());
        $response = new Response($e->getMessage(), 401);
    }

    return $response;
});


$app->run();
