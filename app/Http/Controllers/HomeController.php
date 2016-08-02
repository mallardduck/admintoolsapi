<?php

namespace App\Http\Controllers;

use Storage;
use MaxMind\Db\Reader;
use App\Http\Requests;
use Illuminate\Http\Request;
use Spatie\SslCertificate\SslCertificate;

class HomeController extends Controller
{


    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        $databaseFile = './geoDb.mmdb';
        $reader = new Reader($databaseFile);
        // Get needed vars
        $requesterIp = $request->ips();
        $geoIP = $reader->get($requesterIp[0]);
        $userAgent = $request->header('User-Agent');
        $acceptsContentType = $request->header('Accept');
        $rawVar = $request->input('raw');
        $jsonVars = [
            'ips' => $requesterIp,
            'user-agent' => $userAgent,
            'local-city' => $geoIP['city']['names']['en']
            ];
        if ( (stripos($userAgent, 'curl') !== false && ($acceptsContentType == '*/*')) || ( !is_null($rawVar) && ($rawVar != 0 || $rawVar == "") ) ) {
            return $requesterIp[0];
        }
        return response()->json($jsonVars);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function indexJson(Request $request)
    {
        $databaseFile = './geoDb.mmdb';
        $reader = new Reader($databaseFile);
        // Get needed vars
        $requesterIp = $request->ips();
        $geoIP = $reader->get($requesterIp[0]);
        $userAgent = $request->header('User-Agent');
        $acceptsContentType = $request->header('Accept');
        $rawVar = $request->input('raw');
        $jsonVars = [
            'ips' => $requesterIp,
            'user-agent' => $userAgent,
            'local-city' => $geoIP['city']['names']['en']
            ];
        return response()->json($jsonVars);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function ssltest(Request $request)
    {
        // Get needed vars
        $requesterIp = $request->ips();
        $userAgent = $request->header('User-Agent');
        $acceptsContentType = $request->header('Accept');
        $domain = ($request->input('domain')) ? parse_url($request->input('domain')) : null;
        if ($domain == null) {
            return response()->json(['error' => "Error in request, domain must be provdied", 'code' => 400]);
        }
        $domainIp = gethostbyname($domain['host']);
        if(!filter_var($domainIp, FILTER_VALIDATE_IP))
        {
            return response()->json(['error' => "Domain might be valid, but DNS is not.", 'code' => 200]);
        }
        $certificate = SslCertificate::createForHostName($domain['host'], 5);
        return response()->json(['valid' => $certificate->isValid()]);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function ssltestJson(Request $request)
    {
        // Get needed vars
        $requesterIp = $request->ips();
        $userAgent = $request->header('User-Agent');
        $acceptsContentType = $request->header('Accept');
        $domain = ($request->input('domain')) ? parse_url($request->input('domain')) : null;
        if ($domain == null) {
            return response()->json(['error' => "Error in request, domain must be provdied", 'code' => 400]);
        }
        $domainIp = gethostbyname($domain['host']);
        if(!filter_var($domainIp, FILTER_VALIDATE_IP))
        {
            return response()->json(['error' => "Domain might be valid, but DNS is not.", 'code' => 200]);
        }
        $certificate = SslCertificate::createForHostName($domain['host'], 5);
        $sslRes = [
            'domain' => $domain['host'],
            'domain-ip' => $domainIp,
            'valid' => $certificate->isValid(),
            'ssl-info' => [
                'issuer' => $certificate->getIssuer(),
                'sans' => $certificate->getAdditionalDomains(),
                'valid-from' => $certificate->validFromDate(),
                'valid-to' => $certificate->expirationDate(),
                'expiration-days' => $certificate->expirationDate()->diffInDays()
            ]
        ];
        return response()->json($sslRes);
    }

}
