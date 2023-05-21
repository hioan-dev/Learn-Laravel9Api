<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;

class AuthController extends Controller
{
    function register(Request $request)
    {
       $request->validate([
           'name' => 'required|string',
           'email' => 'required|email|unique:users',
           'password' => 'required|string|min:8'
       ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);
        
        $token = $user->createToken('auth-sanctum')->plainTextToken;

        return response()->json([
        // 'data' => $user,
        // 'access_token' => $token,
        // 'token_type' => 'Bearer',
        'message' => 'User created successfully'
        ], 201);
    }

    function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);
        
        $user = User::where('email', $request->email)->first();
        
        if(!$user || !\Hash::check($request->password, $user->password)){
            return response()->json([
                'message' => 'Bad credentials'
            ], 401);
        }

        $token = $user->createToken('auth-sanctum')->plainTextToken;

        return response()->json([
            'data' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
        ], 200);
    }

    function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logged out'
        ], 200);
    }
}