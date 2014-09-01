<?php

namespace InAppPurchase;

/**
 * Of course, it might be used apart of Symfony
 * then this string is not need
 */
use Symfony\Component\HttpFoundation\Request;

class GoogleInAppPurchase
{
    private $request;
    
    /**
     * Google Play application public key 
     * provided when application is being registered
     * So the value might be assigned to it right here
     * (not it's being passed to constructor as an argument 
     * because this class is a service in the Symfony2's terminology)
     */
    private $googleAppPublicKey;

    private $signature;
    private $purchaseData;

    public function __construct(Request $request, $googleAppPublicKey)
    {
        $this->request = $request;

        $this->googleAppPublicKey = $googleAppPublicKey;

        $this->signature = $request->get('signatureData', null);
        $this->purchaseData = $request->get('purchaseData', null);

        $this->validateRequestParams();
    }

    public function verify()
    {
        $key = sprintf("%s\n%s%s", '-----BEGIN PUBLIC KEY-----',
                                   chunk_split($this->googleAppPublicKey, 64, "\n"),
                                   '-----END PUBLIC KEY-----');

        $publicKey = openssl_get_publickey($key);

        $result = openssl_verify($this->purchaseData, base64_decode($this->signature), $publicKey, OPENSSL_ALGO_SHA1);

        return $result == 1;
    }

    private function validateRequestParams()
    {
        if($this->signature == null) {
            throw new \Exception('Wrong parameters: you have to pass signatureData parameter within request');
        }

        if($this->purchaseData == null) {
            throw new \Exception('Wrong parameters: you have to pass purchaseData parameter within request');
        }
    }
}
