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
        // Get IP info results
        $rawVar = $request->input('raw');
        $results = $this->getIPinfo($request, $rawVar);
        return $results;
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function indexJson(Request $request)
    {
        // Get IP info results
        $results = $this->getIPinfo($request);
        return response()->json($results);
    }

    private function getIPinfo(Request $request, $raw=null) {
        // Get needed vars
        $requesterIp = $request->ips();
        if ( !is_null($raw) && ($raw != 0 || $raw == "") ) {
            return $requesterIp['0'];
        }
        $databaseFile = './geoDb.mmdb';
        $reader = new Reader($databaseFile);
        // Get IP info
        $geoIP = $reader->get($requesterIp[0]);
        $userAgent = $request->header('User-Agent');
        $acceptsContentType = $request->header('Accept');
        return [
            'ips' => $requesterIp,
            'user-agent' => $userAgent,
            'local-city' => $geoIP['city']['names']['en']
            ];
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function sslIndex(Request $request)
    {
        $results = $this->sslchecker($request);
        return response()->json($results);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function sslIndexJson(Request $request)
    {
        $results = $this->sslchecker($request, true);
        return response()->json($results);
    }

    private function sslchecker(Request $request, $full=false) {
        // Get needed vars
        $requesterIp = $request->ips();
        $userAgent = $request->header('User-Agent');
        $acceptsContentType = $request->header('Accept');
        $rawDomain = $request->input('domain');
        // Verify '//' is in input to validate URL properly
        if (!preg_match('#//#', $request->input('domain'))) {
            $rawDomain = '//'.$request->input('domain');
        }
        // Parse URL, appending the '//' helps increase likelyhood we get a host component.
        $domain = ($rawDomain) ? parse_url($rawDomain) : null;
        if (key_exists('host', $domain) == false) {
            return ['error' => "Error in request, proper domain and/or URL must be provdied", 'code' => 400];
        }
        $verifiedDomain = $domain['host'];
        // Attempt to get IP for domain provided and verify it
        $domainIp = gethostbyname($verifiedDomain);
        if(!filter_var($domainIp, FILTER_VALIDATE_IP))
        {
            return ['error' => "Domain might be valid, but DNS is not.", 'code' => 200];
        }
        // Verify SSL
        if ($full=true){
            $certificate = SslCertificate::createForHostName($verifiedDomain, 5);
            $sslRes = [
                'domain' => $verifiedDomain,
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
        } else {
            $sslRes = SslCertificate::createForHostName($verifiedDomain, 5);

        }
        // return output
        return $sslRes;
    }

}
