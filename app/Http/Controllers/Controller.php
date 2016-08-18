<?php

namespace App\Http\Controllers;

use Cache;
use MaxMind\Db\Reader;
use Illuminate\Http\Request;
use Spatie\SslCertificate\SslCertificate;

use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Auth\Access\AuthorizesResources;

class Controller extends BaseController
{
    use AuthorizesRequests, AuthorizesResources, DispatchesJobs, ValidatesRequests;

    // Cache expiration time in minutes
    public $cacheTTL = '120';

      public function getIPinfo(Request $request, $raw = null)
      {
          // Get needed vars
          $requesterIp = $request->ips();
          $userAgent = $request->header('User-Agent');
          $acceptsContentType = $request->header('Accept');
          //If someone is hitting the .json route, they want json so we skip the next check
          if (!$request->is('*.json')) {
              // If curl and using default ContentType header, OR, if raw=true, they get the plain IP
              if ( (stripos($userAgent, 'curl/') !== false && ($acceptsContentType !== 'text/json')) || $raw ) {
                  // Current LW behaviour right here
                  return $requesterIp['0'];
              }
          }
          // If they are on the JSON route, or want JSON, we get them IP info
          // Load the IP DB file, then initilize the reader
          $databaseFile = './geoDb.mmdb';
          $reader = new Reader($databaseFile);
          // Get IP info
          $geoIP = $reader->get($requesterIp[0]);
          // Return full JSON results
          return [
              'ips' => $requesterIp,
              'userAgent' => $userAgent,
              'localCity' => $geoIP['city']['names']['en']
              ];
      }

      public function sslchecker(Request $request, $full = false)
      {
          // Get needed vars
          $requesterIp = $request->ips();
          $userAgent = $request->header('User-Agent');
          $acceptsContentType = $request->header('Accept');
          $rawDomain = $request->input('domain');
          if (gettype($rawDomain) == "NULL" || $rawDomain == "") {
              return ['error' => "Error in request, proper domain and/or URL must be provdied", 'code' => 400];
          }
          // Verify '//' is in input to validate URL properly
          if (!preg_match('#//#', $rawDomain)) {
              // If it's not there, we assume they gave us a FQDN and add it
              $rawDomain = '//'.$request->input('domain');
          }
          // Parse URL -- appending '//' above helps us get a host component.
          $domain = ($rawDomain) ? parse_url($rawDomain) : null;
          // One last sanity check before we validate the DNS
          if (key_exists('host', $domain) == false) {
              return ['error' => "Error in request, proper domain and/or URL must be provdied", 'code' => 400];
          }
          $verifiedDomain = $domain['host'];
          // Attempt to get IP for domain provided and verify it
          $domainIp = gethostbyname($verifiedDomain);
          if (!filter_var($domainIp, FILTER_VALIDATE_IP)) {
              return ['error' => "Domain might be valid, but DNS is not.", 'code' => 200];
          }
          // If we had an IP, we can check to verify an SSL
          if ($full == true) {

              $certificate = Cache::remember($verifiedDomain, $this->cacheTTL, function() use ($verifiedDomain) {
                  return SslCertificate::createForHostName($verifiedDomain, 5);
              });

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
              $validBoolean = Cache::remember('quick-'.$verifiedDomain, $this->cacheTTL, function() use ($verifiedDomain) {
                  return SslCertificate::createForHostName($verifiedDomain, 5)->isValid();
              });
              // akin to the 'raw' IP style, we are brief
              $sslRes = ($validBoolean) ? 'Valid' : 'Invalid';
          }
          // return output
          return $sslRes;
      }

}
