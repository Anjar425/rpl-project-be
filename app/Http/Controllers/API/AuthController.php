<?php

namespace App\Http\Controllers\API;

use Illuminate\Http\Request;
use App\Http\Controllers\API\BaseController as BaseController;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends BaseController
{
    /**
     * Register api
     *
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required',
            'c_password' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return $this->sendError('Validation Error.', $validator->errors());
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);

        $user = User::create($input);

        event(new Registered($user));

        $success['token'] =  $user->createToken('MyApp')->plainTextToken;
        $success['name'] =  $user->name;

        return $this->sendResponse($success, 'User register successfully.');
    }

    /**
     * Login api
     *
     * @return \Illuminate\Http\Response
     */

    public function login(Request $request)
    {

        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            /** @var \App\Models\User $user **/
            $user = Auth::user();
            $success['token'] =  $user->createToken('MyApp')->plainTextToken;
            $success['name'] =  $user->name;

            return $this->sendResponse($success, 'User login successfully.');
        } else {
            return $this->sendError('Unauthorised.', ['error' => ['unauthorised']]);
        }
    }

    public function logout(Request $request){
        $user = $request->user();
        $user->currentAccessToken()->delete();
        $response = [
           'success'   => true,
           'message'   => 'Berhasil Logout'
        ];
        return response($response, 200);
    }

    /**
     * send verification email
     *
     * @return \Illuminate\Http\Response
     */
    public function sendVerificationEmail(Request $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return $this->sendResponse('Already Verified', 'Already Verified');
        }

        $request->user()->sendEmailVerificationNotification();

        return $this->sendResponse('Verification Link Sent', 'Verification Link Sent');
    }


    /**
     * verify email
     *
     * @return \Illuminate\Http\Response
     */
    public function verify(EmailVerificationRequest $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return $this->sendResponse('Email already verified', 'Email already verified');
        }

        if ($request->user()->markEmailAsVerified()) {
            event(new Verified($request->user()));
        }
        return $this->sendResponse('Email has been verified', 'Email has been verified');
    }
}
