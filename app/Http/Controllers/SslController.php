<?php

namespace App\Http\Controllers;

use App\Http\Requests;
use Illuminate\Http\Request;

class SslController extends Controller
{
  /**
   * Display a listing of the resource.
   *
   * @return \Illuminate\Http\Response
   */
  public function index(Request $request)
  {
      $results = parent::sslchecker($request);
      return response()->json($results);
  }

  /**
   * Display a listing of the resource.
   *
   * @return \Illuminate\Http\Response
   */
  public function indexJson(Request $request)
  {
      $results = parent::sslchecker($request, true);
      return response()->json($results);
  }

}
