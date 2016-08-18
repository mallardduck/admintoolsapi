<?php

namespace App\Http\Controllers;

use App\Http\Requests;
use Illuminate\Http\Request;
use Spatie\SslCertificate\SslCertificate;

class SslController extends Controller
{
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

  private function sslchecker(Request $request, $full = false)
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
          $validBoolean = SslCertificate::createForHostName($verifiedDomain, 5)->isValid();
          // akin to the 'raw' IP style, we are brief
          $sslRes = ($validBoolean) ? 'Valid' : 'Invalid';
      }
      // return output
      return $sslRes;
  }
}
