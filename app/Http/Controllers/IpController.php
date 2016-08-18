<?php

namespace App\Http\Controllers;

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
      $results = (gettype($rawVar) !== "NULL") ? parent::getIPinfo($request, true) : parent::getIPinfo($request);
      // I don't care about raw=0, raw=false; this is the default state
      return $results;
  }

}
