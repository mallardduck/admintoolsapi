<?php

namespace App\Http\Controllers;

use MaxMind\Db\Reader;
use App\Http\Requests;
use Illuminate\Http\Request;

class IpController extends Controller
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
      // If the rawVar is anything BUT null we pass true
      $results = (gettype($rawVar) !== "NULL") ? $this->getIPinfo($request, true) : $this->getIPinfo($request);
      // I don't care about raw=0, raw=false; this is the default state
      return $results;
  }

  private function getIPinfo(Request $request, $raw = null)
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
          'user-agent' => $userAgent,
          'local-city' => $geoIP['city']['names']['en']
          ];
  }
}
