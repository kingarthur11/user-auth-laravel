<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use App\Mail\SendEmail;
use App\Models\User;
use Laravel\Passport\Client as OClient;
use GuzzleHttp\Client;
use App\OauthAccessToken;
use Illuminate\Foundation\Application;
use Illuminate\Support\Str;

use Hash;
use Validator;
use Auth;
use DB;

class UserController extends Controller
{
    public function __construct(Application $app)
    {
        $this->app = $app;
    }
    protected function register(Request $request)
    {
        $input = $request->all();

        $validation = Validator::make($input, [
            'full_name' => 'required|string|max:255',
            'phone_number' => 'required|string|max:255',
            'email' => 'required|string|email|max:255',
            'password' => 'required|min:6',
            'password_confirmation' => 'required|same:password',
        ]);

        if($validation->fails()){
            return response()->json(json_decode($validation->errors(), true));
        }

        $user = User::where('email', $input['email'])
                        ->orWhere('phone_number', $input['phone_number'])
                        ->first();

        if (!$user) {
            $input['password'] = Hash::make($input['password']);
            $input['remember_token'] = Str::random(10);
            $client = User::create($input);
            return response()->json(['status' => 'success', 'client' => $client], 200);
        } else {
            $response = ["message" =>'User already exist'];
            return response($response, 422);
        }
    }


    public function login(Request $request)
    {
        $input = $request->all();

        $validation = Validator::make($input, [
            'phone_number' => 'required',
            'password' => 'required',
        ]);

        $fieldType = filter_var($request->phone_number, FILTER_VALIDATE_EMAIL) ? 'email' : 'phone_number';

        $user = User::where('email', $input['phone_number'])
                        ->orWhere('phone_number', $input['phone_number'])
                        ->first();
        if ($user) {
            if (Hash::check($request->password, $user->password)) {
                $token = $user->createToken('Laravel Password Grant Client')->accessToken;

                return response()->json([
                    'status' => 'success',
                    'token' => $token,
                    'user' => $user,
                ], 200);
            } else {
                $response = ["message" => "Password mismatch"];
                return response($response, 422);
            }
        } else {
            $response = ["message" =>'User does not exist'];
            return response($response, 422);
        }

    }
    public function index()
    {
        $client = User::orderBy('id', 'desc')->get();

        if($client){
           return response()->json($client);
        }else{
            return response()->json([
                'status'=>'failure',
                'message' => 'An error occurred'
            ], 500);
        }
    }

    public function update(Request $request)
    {
        $input = $request->all();
        $validation = Validator::make($input, [
            'full_name' => 'required|string|max:255',
            'phone_number' => 'required|string|max:255',
            'email' => 'required|string|max:255',
            'old_password' => 'required|min:6',
            'password' => 'required|min:6',
            'password_confirmation' => 'required|same:password',
        ]);
        if($validation->fails()){
            return response()->json(json_decode($validation->errors(), true));
        }

        $input['user_id'] = Auth::id();
        $user = User::find($input['user_id']);

        if(Hash::check($input['old_password'], $user->password)){
            $input['password'] = Hash::make($input['password']);
            User::where('id', $user->id)->update([
                'password' => $input['password'],
                'email' => $input['email'],
                'phone_number' => $input['phone_number'],
                'full_name' => $input['full_name'],
              ]);
            return response()->json([
                'status' => 'success',
                    'message' => 'Password updated successfully'
                ]);
        }
        return response()->json([
            'status' => 'failure',
            'valid' => false,
            'message' => 'password does exist'
        ], 400);

    }

    public function show($id)
    {
        $staff = User::find($id);
        if ($staff) {
            return response()->json($staff);
        }
    }

    public function destroy($id)
    {
        $user = User::find($id);
        $user->delete();

        return response()->json([
           'status' => 'success',
           'user' => 'User Deleted successfully'
        ], 200);

    }
}

