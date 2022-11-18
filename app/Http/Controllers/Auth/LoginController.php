<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\Setting;
use App\Models\User;
use App\Models\Ldap;
use App\Services\Saml;
use Com\Tecnick\Barcode\Barcode;
use Google2FA;
use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Validator;
use Log;
use Redirect;
use File;
use Storage;
use Laravel\Socialite\Facades\Socialite as Socialite;

/**
 * This controller handles authentication for the user, including local
 * database users and LDAP users.
 *
 * @author [A. Gianotto] [<snipe@snipe.net>]
 * @version    v1.0
 */
class LoginController extends Controller
{
<<<<<<< HEAD

  use ThrottlesLogins;
=======
    use ThrottlesLogins;
>>>>>>> master

  // This tells the auth controller to use username instead of email address
  protected $username = 'username';

  /**
   * Where to redirect users after login / registration.
   *
   * @var string
   */
  protected $redirectTo = '/';

<<<<<<< HEAD
  /**
   * @var LdapAd
   */
  protected $ldap;

  /**
   * @var Saml
   */
  protected $saml;

  /**
   * Create a new authentication controller instance.
   *
   * @param LdapAd $ldap
   * @param Saml $saml
   *
   * @return void
   */
  public function __construct(/*LdapAd $ldap, */Saml $saml)
  {
    parent::__construct();
    $this->middleware('guest', ['except' => ['logout', 'postTwoFactorAuth', 'getTwoFactorAuth', 'getTwoFactorEnroll']]);
    Session::put('backUrl', \URL::previous());
    // $this->ldap = $ldap;
    $this->saml = $saml;
  }

  function showLoginForm(Request $request)
  {
    $this->loginViaRemoteUser($request);
    $this->loginViaSaml($request);
    if (Auth::check()) {
      return redirect()->intended('/');
    }

    if ($this->saml->isEnabled() && Setting::getSettings()->saml_forcelogin == "1" && !($request->has('nosaml') || $request->session()->has('error'))) {
      return redirect()->route('saml.login');
    }

    if (Setting::getSettings()->login_common_disabled == "1") {
      return view('errors.403');
    }

    return view('auth.login');
  }

  /**
   * Log in a user by SAML
   * 
   * @author Johnson Yi <jyi.dev@outlook.com>
   * 
   * @since 5.0.0
   *
   * @param Request $request
   * 
   * @return User
   * 
   * @throws \Exception
   */
  private function loginViaSaml(Request $request)
  {
    $saml = $this->saml;
    $samlData = $request->session()->get('saml_login');
    if ($saml->isEnabled() && !empty($samlData)) {
      try {
        Log::debug("Attempting to log user in by SAML authentication.");
        $user = $saml->samlLogin($samlData);
        if (!is_null($user)) {
          Auth::login($user, true);
        } else {
          $username = $saml->getUsername();
          \Log::warning("SAML user '$username' could not be found in database.");
          $request->session()->flash('error', trans('auth/message.signin.error'));
          $saml->clearData();
=======
    /**
     * @var Saml
     */
    protected $saml;

    /**
     * Create a new authentication controller instance.
     *
     * @param Saml $saml
     *
     * @return void
     */
    public function __construct(Saml $saml)
    {
        parent::__construct();
        $this->middleware('guest', ['except' => ['logout', 'postTwoFactorAuth', 'getTwoFactorAuth', 'getTwoFactorEnroll']]);
        Session::put('backUrl', \URL::previous());
        // $this->ldap = $ldap;
        $this->saml = $saml;
    }

    public function showLoginForm(Request $request)
    {
        $this->loginViaRemoteUser($request);
        $this->loginViaSaml($request);
        if (Auth::check()) {
            return redirect()->intended('/');
        }

        if (!$request->session()->has('loggedout')) {
            // If the environment is set to ALWAYS require SAML, go straight to the SAML route.
            // We don't need to check other settings, as this should override those.
            if (config('app.require_saml')) {
                return redirect()->route('saml.login');
            }


            if ($this->saml->isEnabled() && Setting::getSettings()->saml_forcelogin == '1' && ! ($request->has('nosaml') || $request->session()->has('error'))) {
                return redirect()->route('saml.login');
            }
        }

        if (Setting::getSettings()->login_common_disabled == '1') {
            \Log::debug('login_common_disabled is set to 1 - return a 403');
            return view('errors.403');
        }

        return view('auth.login');
    }

    /**
     * Log in a user by SAML
     *
     * @author Johnson Yi <jyi.dev@outlook.com>
     *
     * @since 5.0.0
     *
     * @param Request $request
     *
     * @return User
     *
     * @throws \Exception
     */
    private function loginViaSaml(Request $request)
    {
        $saml = $this->saml;
        $samlData = $request->session()->get('saml_login');

        if ($saml->isEnabled() && ! empty($samlData)) {

            try {
                $user = $saml->samlLogin($samlData);

                if (!is_null($user)) {
                    Auth::login($user);
                } else {
                    $username = $saml->getUsername();
                    \Log::debug("SAML user '$username' could not be found in database.");
                    $request->session()->flash('error', trans('auth/message.signin.error'));
                    $saml->clearData();
                }

                if ($user = Auth::user()) {
                    $user->last_login = \Carbon::now();
                    $user->save();
                }
                
            } catch (\Exception $e) {
                \Log::debug('There was an error authenticating the SAML user: '.$e->getMessage());
                throw new \Exception($e->getMessage());
            }

        // Fallthrough with better logging
        } else {

            // Better logging
            if (!$saml->isEnabled()) {
                \Log::debug("SAML page requested, but SAML does not seem to enabled.");
            } else {
                \Log::debug("SAML page requested, but samlData seems empty.");
            }
        }



    }

    /**
     * Log in a user by LDAP
     *
     * @author Wes Hulette <jwhulette@gmail.com>
     *
     * @since 5.0.0
     *
     * @param Request $request
     *
     * @return User
     *
     * @throws \Exception
     */
    private function loginViaLdap(Request $request): User
    {
        Log::debug("Binding user to LDAP.");
         $ldap_user = Ldap::findAndBindUserLdap($request->input('username'), $request->input('password'));
         if (!$ldap_user) {
             Log::debug("LDAP user ".$request->input('username')." not found in LDAP or could not bind");
             throw new \Exception("Could not find user in LDAP directory");
         } else {
             Log::debug("LDAP user ".$request->input('username')." successfully bound to LDAP");
         }

         // Check if the user already exists in the database and was imported via LDAP
         $user = User::where('username', '=', $request->input('username'))->whereNull('deleted_at')->where('ldap_import', '=', 1)->where('activated', '=', '1')->first(); // FIXME - if we get more than one we should fail. and we sure about this ldap_import thing?
         Log::debug("Local auth lookup complete");

         // The user does not exist in the database. Try to get them from LDAP.
         // If user does not exist and authenticates successfully with LDAP we
         // will create it on the fly and sign in with default permissions
         if (!$user) {
             Log::debug("Local user ".$request->input('username')." does not exist");
             Log::debug("Creating local user ".$request->input('username'));

             if ($user = Ldap::createUserFromLdap($ldap_user, $request->input('password'))) {
                 Log::debug("Local user created.");
             } else {
                 Log::debug("Could not create local user.");
                 throw new \Exception("Could not create local user");
             }
             // If the user exists and they were imported from LDAP already
         } else {
             Log::debug("Local user ".$request->input('username')." exists in database. Updating existing user against LDAP.");

             $ldap_attr = Ldap::parseAndMapLdapAttributes($ldap_user);

            if (Setting::getSettings()->ldap_pw_sync=='1') {
                $user->password = bcrypt($request->input('password'));
            }
            $user->email = $ldap_attr['email'];
            $user->first_name = $ldap_attr['firstname'];
            $user->last_name = $ldap_attr['lastname']; //FIXME (or TODO?) - do we need to map additional fields that we now support? E.g. country, phone, etc.
            $user->save();
        } // End if(!user)
        return $user;
    }

    private function loginViaRemoteUser(Request $request)
    {
        $header_name = Setting::getSettings()->login_remote_user_header_name ?: 'REMOTE_USER';
        $remote_user = $request->server($header_name);
        if (!isset($remote_user)) {
          $remote_user = $request->server('REDIRECT_'.$header_name);
        }
        if (Setting::getSettings()->login_remote_user_enabled == '1' && isset($remote_user) && ! empty($remote_user)) {
            Log::debug("Authenticating via HTTP header $header_name.");

            $strip_prefixes = [
                // IIS/AD
                // https://github.com/snipe/snipe-it/pull/5862
                '\\',

                // Google Cloud IAP
                // https://cloud.google.com/iap/docs/identity-howto#getting_the_users_identity_with_signed_headers
                'accounts.google.com:',
            ];

            $pos = 0;
            foreach ($strip_prefixes as $needle) {
                if (($pos = strpos($remote_user, $needle)) !== false) {
                    $pos += strlen($needle);
                    break;
                }
            }

            if ($pos > 0) {
                $remote_user = substr($remote_user, $pos);
            }

            try {
                $user = User::where('username', '=', $remote_user)->whereNull('deleted_at')->where('activated', '=', '1')->first();
                Log::debug('Remote user auth lookup complete');
                if (! is_null($user)) {
                    Auth::login($user, $request->input('remember'));
                }
            } catch (Exception $e) {
                Log::debug('There was an error authenticating the Remote user: '.$e->getMessage());
            }
        }
    }

    /**
     * Account sign in form processing.
     *
     * @return Redirect
     */
    public function login(Request $request)
    {

        //If the environment is set to ALWAYS require SAML, return access denied
        if (config('app.require_saml')) {
            \Log::debug('require SAML is enabled in the .env - return a 403');
            return view('errors.403');
        }

        if (Setting::getSettings()->login_common_disabled == '1') {
            \Log::debug('login_common_disabled is set to 1 - return a 403');
            return view('errors.403');
        }

        $validator = $this->validator($request->all());

        if ($validator->fails()) {
            return redirect()->back()->withInput()->withErrors($validator);
        }

        $this->maxLoginAttempts = config('auth.passwords.users.throttle.max_attempts');
        $this->lockoutTime = config('auth.passwords.users.throttle.lockout_duration');

        if ($lockedOut = $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        $user = null;

        // Should we even check for LDAP users?
        if (Setting::getSettings()->ldap_enabled) { // avoid hitting the $this->ldap
            LOG::debug('LDAP is enabled.');
            try {
                LOG::debug('Attempting to log user in by LDAP authentication.');
                $user = $this->loginViaLdap($request);
                Auth::login($user, $request->input('remember'));

                // If the user was unable to login via LDAP, log the error and let them fall through to
            // local authentication.
            } catch (\Exception $e) {
                Log::debug('There was an error authenticating the LDAP user: '.$e->getMessage());
            }
        }

        // If the user wasn't authenticated via LDAP, skip to local auth
        if (! $user) {
            Log::debug('Authenticating user against database.');
            // Try to log the user in
            if (! Auth::attempt(['username' => $request->input('username'), 'password' => $request->input('password'), 'activated' => 1], $request->input('remember'))) {
                if (! $lockedOut) {
                    $this->incrementLoginAttempts($request);
                }

                Log::debug('Local authentication failed.');

                return redirect()->back()->withInput()->with('error', trans('auth/message.account_not_found'));
            } else {
                $this->clearLoginAttempts($request);
            }
>>>>>>> master
        }

        if ($user = Auth::user()) {
          $user->last_login = \Carbon::now();
          $user->save();
        }
      } catch (\Exception $e) {
        \Log::warning("There was an error authenticating the SAML user: " . $e->getMessage());
        throw new \Exception($e->getMessage());
      }
    }
  }

  /**
   * Log in a user by LDAP
   * 
   * @author Wes Hulette <jwhulette@gmail.com>
   * 
   * @since 5.0.0
   *
   * @param Request $request
   * 
   * @return User
   * 
   * @throws \Exception
   */
  private function loginViaLdap(Request $request): User
  {
    $ldap = \App::make(LdapAd::class);
    try {
      return $ldap->ldapLogin($request->input('username'), $request->input('password'));
    } catch (\Exception $ex) {
      LOG::debug("LDAP user login: " . $ex->getMessage());
      throw new \Exception($ex->getMessage());
    }
  }

  private function loginViaRemoteUser(Request $request)
  {
    $header_name = Setting::getSettings()->login_remote_user_header_name ?: 'REMOTE_USER';
    $remote_user = $request->server($header_name);
    if (Setting::getSettings()->login_remote_user_enabled == "1" && isset($remote_user) && !empty($remote_user)) {
      Log::debug("Authenticating via HTTP header $header_name.");

      $strip_prefixes = [
        // IIS/AD
        // https://github.com/snipe/snipe-it/pull/5862
        '\\',

        // Google Cloud IAP
        // https://cloud.google.com/iap/docs/identity-howto#getting_the_users_identity_with_signed_headers
        'accounts.google.com:',
      ];

      $pos = 0;
      foreach ($strip_prefixes as $needle) {
        if (($pos = strpos($remote_user, $needle)) !== FALSE) {
          $pos += strlen($needle);
          break;
        }
      }

      if ($pos > 0) {
        $remote_user = substr($remote_user, $pos);
      };

      try {
        $user = User::where('username', '=', $remote_user)->whereNull('deleted_at')->where('activated', '=', '1')->first();
        Log::debug("Remote user auth lookup complete");
        if (!is_null($user)) Auth::login($user, true);
      } catch (Exception $e) {
        Log::debug("There was an error authenticating the Remote user: " . $e->getMessage());
      }
    }
  }

  /**
   * Account sign in form processing.
   *
   * @return Redirect
   */
  public function login(Request $request)
  {
    if (Setting::getSettings()->login_common_disabled == "1") {
      return view('errors.403');
    }

    $validator = $this->validator($request->all());

    if ($validator->fails()) {
      return redirect()->back()->withInput()->withErrors($validator);
    }

    $this->maxLoginAttempts = config('auth.passwords.users.throttle.max_attempts');
    $this->lockoutTime = config('auth.passwords.users.throttle.lockout_duration');

    if ($lockedOut = $this->hasTooManyLoginAttempts($request)) {
      $this->fireLockoutEvent($request);
      return $this->sendLockoutResponse($request);
    }

    $user = null;

    // Should we even check for LDAP users?
    if (Setting::getSettings()->ldap_enabled) { // avoid hitting the $this->ldap
      LOG::debug("LDAP is enabled.");
      try {
        LOG::debug("Attempting to log user in by LDAP authentication.");
        $user = $this->loginViaLdap($request);
        Auth::login($user, true);

        // If the user was unable to login via LDAP, log the error and let them fall through to
        // local authentication.
      } catch (\Exception $e) {
        Log::debug("There was an error authenticating the LDAP user: " . $e->getMessage());
      }
    }

    // If the user wasn't authenticated via LDAP, skip to local auth
    if (!$user) {
      Log::debug("Authenticating user against database.");
      // Try to log the user in
      if (!Auth::attempt(['username' => $request->input('username'), 'password' => $request->input('password'), 'activated' => 1], $request->input('remember'))) {

        if (!$lockedOut) {
          $this->incrementLoginAttempts($request);
        }

        Log::debug("Local authentication failed.");
        return redirect()->back()->withInput()->with('error', trans('auth/message.account_not_found'));
      } else {

        $this->clearLoginAttempts($request);
      }
    }

    if ($user = Auth::user()) {
      $user->last_login = \Carbon::now();
      $user->activated = 1;
      $user->save();
    }
    // Redirect to the users page
    return redirect()->intended()->with('success', trans('auth/message.signin.success'));
  }


  /**
   * Two factor enrollment page
   *
   * @return Redirect
   */
  public function getTwoFactorEnroll()
  {

    // Make sure the user is logged in
    if (!Auth::check()) {
      return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
    }


    $settings = Setting::getSettings();
    $user = Auth::user();

<<<<<<< HEAD
    // We wouldn't normally see this page if 2FA isn't enforced via the
    // \App\Http\Middleware\CheckForTwoFactor middleware AND if a device isn't enrolled,
    // but let's check check anyway in case there's a browser history or back button thing.
    // While you can access this page directly, enrolling a device when 2FA isn't enforced
    // won't cause any harm.

    if (($user->two_factor_secret != '') && ($user->two_factor_enrolled == 1)) {
      return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.already_enrolled'));
    }

    $secret = Google2FA::generateSecretKey();
    $user->two_factor_secret = $secret;
    $user->save();

    $barcode = new Barcode();
    $barcode_obj =
      $barcode->getBarcodeObj(
        'QRCODE',
        sprintf(
          'otpauth://totp/%s:%s?secret=%s&issuer=Snipe-IT&period=30',
          urlencode($settings->site_name),
          urlencode($user->username),
          urlencode($secret)
        ),
        300,
        300,
        'black',
        [-2, -2, -2, -2]
      );

    return view('auth.two_factor_enroll')->with('barcode_obj', $barcode_obj);
  }


  /**
   * Two factor code form page
   *
   * @return Redirect
   */
  public function getTwoFactorAuth()
  {
    // Check that the user is logged in
    if (!Auth::check()) {
      return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
    }
=======
        // Make sure the user is logged in
        if (! Auth::check()) {
            return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
        }

        $settings = Setting::getSettings();
        $user = Auth::user();
>>>>>>> master

    $user = Auth::user();

<<<<<<< HEAD
    // Check whether there is a device enrolled.
    // This *should* be handled via the \App\Http\Middleware\CheckForTwoFactor middleware
    // but we're just making sure (in case someone edited the database directly, etc)
    if (($user->two_factor_secret == '') || ($user->two_factor_enrolled != 1)) {
      return redirect()->route('two-factor-enroll');
    }

    return view('auth.two_factor');
  }
=======
        if (($user->two_factor_secret != '') && ($user->two_factor_enrolled == 1)) {
            return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.already_enrolled'));
        }

        $secret = Google2FA::generateSecretKey();
        $user->two_factor_secret = $secret;
>>>>>>> master

  /**
   * Two factor code submission
   *
   * @param Request $request
   *
   * @return Redirect
   */
  public function postTwoFactorAuth(Request $request)
  {

<<<<<<< HEAD
    if (!Auth::check()) {
      return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
    }

    if (!$request->filled('two_factor_secret')) {
      return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.code_required'));
    }

    if (!$request->has('two_factor_secret')) {
      return redirect()->route('two-factor')->with('error', 'Two-factor code is required.');
    }

    $user = Auth::user();
    $secret = $request->input('two_factor_secret');

    if (Google2FA::verifyKey($user->two_factor_secret, $secret)) {
      $user->two_factor_enrolled = 1;
      $user->save();
      $request->session()->put('2fa_authed', 'true');
      return redirect()->route('home')->with('success', 'You are logged in!');
    }

    return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.invalid_code'));
  }


  /**
   * Logout page.
   *
   * @param Request $request
   *
   * @return Redirect
   */
  public function logout(Request $request)
  {
    $settings = Setting::getSettings();
    $saml = $this->saml;
    $sloRedirectUrl = null;
    $sloRequestUrl = null;

    if ($saml->isEnabled()) {
      $auth = $saml->getAuth();
      $sloRedirectUrl = $request->session()->get('saml_slo_redirect_url');

      if (!empty($auth->getSLOurl()) && $settings->saml_slo == '1' && $saml->isAuthenticated()  && empty($sloRedirectUrl)) {
        $sloRequestUrl = $auth->logout(null, array(), $saml->getNameId(), $saml->getSessionIndex(), true, $saml->getNameIdFormat(), $saml->getNameIdNameQualifier(), $saml->getNameIdSPNameQualifier());
      }

      $saml->clearData();
    }

    if (!empty($sloRequestUrl)) {
      return redirect()->away($sloRequestUrl);
    }

    $request->session()->regenerate(true);

    $request->session()->regenerate(true);
    Auth::logout();

    if (!empty($sloRedirectUrl)) {
      return redirect()->away($sloRedirectUrl);
    }

    $customLogoutUrl = $settings->login_remote_user_custom_logout_url;
    if ($settings->login_remote_user_enabled == '1' && $customLogoutUrl != '') {
      return redirect()->away($customLogoutUrl);
    }

    return redirect()->route('login')->with(['success' => trans('auth/message.logout.success'), 'loggedout' => true]);
  }


  /**
   * Get a validator for an incoming registration request.
   *
   * @param  array  $data
   * @return \Illuminate\Contracts\Validation\Validator
   */
  protected function validator(array $data)
  {
    return Validator::make($data, [
      'username' => 'required',
      'password' => 'required',
    ]);
  }


  public function username()
  {
    return 'username';
  }

  /**
   * Redirect the user after determining they are locked out.
   *
   * @param  \Illuminate\Http\Request  $request
   * @return \Illuminate\Http\RedirectResponse
   */
  protected function sendLockoutResponse(Request $request)
  {
    $seconds = $this->limiter()->availableIn(
      $this->throttleKey($request)
    );

    $minutes = round($seconds / 60);

    $message = \Lang::get('auth/message.throttle', ['minutes' => $minutes]);

    return redirect()->back()
      ->withInput($request->only($this->username(), 'remember'))
      ->withErrors([$this->username() => $message]);
  }


  /**
   * Override the lockout time and duration
   *
   * @param  \Illuminate\Http\Request  $request
   * @return bool
   */
  protected function hasTooManyLoginAttempts(Request $request)
  {
    $lockoutTime = config('auth.passwords.users.throttle.lockout_duration');
    $maxLoginAttempts = config('auth.passwords.users.throttle.max_attempts');

    return $this->limiter()->tooManyAttempts(
      $this->throttleKey($request),
      $maxLoginAttempts,
      $lockoutTime
    );
  }

  public function legacyAuthRedirect()
  {
    return redirect()->route('login');
  }

  public function redirectTo()
  {
    return Session::get('backUrl') ? Session::get('backUrl') :   $this->redirectTo;
  }

  public function google()
  {
    return Socialite::driver('google')->redirect();
  }

  public function googleCallback()
  {
    try {
      $google = Socialite::driver('google')->stateless()->user();
    } catch (Exception $e) {
      return redirect('/');
    }

    $user = User::where('google_id', $google->getId())->first();

    if (!$user) {
      // User Creation from google OAUTH2 information
      $user = User::create([
        'google_id' => $google->getId(),
        'activated' => 1,
        'first_name' => explode(' ', $google->getName())[0],
        'last_name' => explode(' ', $google->getName())[1],
        'username' => substr(explode(' ', $google->getName())[0], 0, 1)
          . explode(' ', $google->getName())[1],
        'email' => $google->getEmail(),
        'password' => bcrypt($google->getId()),
        //FIXME ugly fix to set the permissions from group (sql below)
        'permissions' => '{"superuser":"0","admin":"0","import":"0","reports.view":"0","assets.view":"0","assets.create":"0","assets.edit":"0","assets.delete":"0","assets.checkin":"0","assets.checkout":"0","assets.audit":"0","assets.view.requestable":"0","accessories.view":"0","accessories.create":"0","accessories.edit":"0","accessories.delete":"0","accessories.checkout":"0","accessories.checkin":"0","consumables.view":"0","consumables.create":"0","consumables.edit":"0","consumables.delete":"0","consumables.checkout":"0","licenses.view":"0","licenses.create":"0","licenses.edit":"0","licenses.delete":"0","licenses.checkout":"0","licenses.keys":"0","components.view":"0","components.create":"0","components.edit":"0","components.delete":"0","components.checkout":"0","components.checkin":"0","users.view":"0","users.create":"0","users.edit":"0","users.delete":"0","models.view":"0","models.create":"0","models.edit":"0","models.delete":"0","categories.view":"0","categories.create":"0","categories.edit":"0","categories.delete":"0","departments.view":"0","departments.create":"0","departments.edit":"0","departments.delete":"0","statuslabels.view":"0","statuslabels.create":"0","statuslabels.edit":"0","statuslabels.delete":"0","customfields.view":"0","customfields.create":"0","customfields.edit":"0","customfields.delete":"0","suppliers.view":"0","suppliers.create":"0","suppliers.edit":"0","suppliers.delete":"0","manufacturers.view":"0","manufacturers.create":"0","manufacturers.edit":"0","manufacturers.delete":"0","depreciations.view":"0","depreciations.create":"0","depreciations.edit":"0","depreciations.delete":"0","locations.view":"0","locations.create":"0","locations.edit":"0","locations.delete":"0","companies.view":"0","companies.create":"0","companies.edit":"0","companies.delete":"0","self.two_factor":"0","self.api":"0","self.edit_location":"0"}',
        'avatar' => strtolower(explode(' ', $google->getName())[0])  . "-" . strtolower(explode(' ', $google->getName())[1]) . ".png",
        'profile_pic' => $google->getAvatar(),
      ]);

      // user picture upload to set as avatar
      $url = $user['profile_pic'];
      $contents = file_get_contents($url);
      $file = public_path() . '/uploads/avatars/' . strtolower(explode(' ', $google->getName())[0])  . "-" . strtolower(explode(' ', $google->getName())[1]) . ".png";
      $upload = file_put_contents($file, $contents);

      // bit of SQL to get the new user's ID and put it with the "simple users" group id in users_groups table
      $userGoogleId = $google->getId();
      $userId = DB::table('users')->where('google_id', $userGoogleId)->value('id');
      DB::table('users_groups')->insert(['user_id' => $userId, 'group_id' => 2]);

      // bit of log to show what user has just been created
      Log::notice('########### New User created  : ');
      Log::notice('########### FirstName         : ' . explode(' ', $google->getName())[0]);
      Log::notice('########### LastName          : ' . explode(' ', $google->getName())[1]);
      Log::notice('########### Google id         : ' . $google->getId());
      Log::notice('########### email             : ' . $google->getEmail());
      Log::notice('########### avatar            : ' . $google->getAvatar());
    }


    auth()->login($user);
    return redirect()->intended('/');
  }
=======
        $user->save(); // make sure to save *AFTER* displaying the barcode, or else we might save a two_factor_secret that we never actually displayed to the user if the barcode fails

        return view('auth.two_factor_enroll')->with('barcode_obj', $barcode_obj);
    }

    /**
     * Two factor code form page
     *
     * @return Redirect
     */
    public function getTwoFactorAuth()
    {
        // Check that the user is logged in
        if (! Auth::check()) {
            return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
        }

        $user = Auth::user();

        // Check whether there is a device enrolled.
        // This *should* be handled via the \App\Http\Middleware\CheckForTwoFactor middleware
        // but we're just making sure (in case someone edited the database directly, etc)
        if (($user->two_factor_secret == '') || ($user->two_factor_enrolled != 1)) {
            return redirect()->route('two-factor-enroll');
        }

        return view('auth.two_factor');
    }

    /**
     * Two factor code submission
     *
     * @param Request $request
     *
     * @return Redirect
     */
    public function postTwoFactorAuth(Request $request)
    {
        if (! Auth::check()) {
            return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
        }

        if (! $request->filled('two_factor_secret')) {
            return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.code_required'));
        }

        if (! $request->has('two_factor_secret')) { // TODO this seems almost the same as above?
            return redirect()->route('two-factor')->with('error', 'Two-factor code is required.');
        }

        $user = Auth::user();
        $secret = $request->input('two_factor_secret');

        if (Google2FA::verifyKey($user->two_factor_secret, $secret)) {
            $user->two_factor_enrolled = 1;
            $user->save();
            $request->session()->put('2fa_authed', $user->id);

            return redirect()->route('home')->with('success', 'You are logged in!');
        }

        return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.invalid_code'));
    }


    /**
     * Logout page.
     *
     * @param Request $request
     *
     * @return Redirect
     */
    public function logout(Request $request)
    {
        // Logout is only allowed with a http POST but we need to allow GET for SAML SLO
        $settings = Setting::getSettings();
        $saml = $this->saml;
        $samlLogout = $request->session()->get('saml_logout');
        $sloRedirectUrl = null;
        $sloRequestUrl = null;
    
        // Only allow GET if we are doing SAML SLO otherwise abort with 405
        if ($request->isMethod('GET') && !$samlLogout) {
            abort(405);
        }

        if ($saml->isEnabled()) {
            $auth = $saml->getAuth();
            $sloRedirectUrl = $request->session()->get('saml_slo_redirect_url');

            if (! empty($auth->getSLOurl()) && $settings->saml_slo == '1' && $saml->isAuthenticated() && empty($sloRedirectUrl)) {
                $sloRequestUrl = $auth->logout(null, [], $saml->getNameId(), $saml->getSessionIndex(), true, $saml->getNameIdFormat(), $saml->getNameIdNameQualifier(), $saml->getNameIdSPNameQualifier());
            }

            $saml->clearData();
        }

        if (! empty($sloRequestUrl)) {
            return redirect()->away($sloRequestUrl);
        }

        $request->session()->regenerate(true);

        if ($request->session()->has('password_hash_'.Auth::getDefaultDriver())){
            $request->session()->remove('password_hash_'.Auth::getDefaultDriver());
        }

        Auth::logout();

        if (! empty($sloRedirectUrl)) {
            return redirect()->away($sloRedirectUrl);
        }

        $customLogoutUrl = $settings->login_remote_user_custom_logout_url;
        if ($settings->login_remote_user_enabled == '1' && $customLogoutUrl != '') {
            return redirect()->away($customLogoutUrl);
        }

        return redirect()->route('login')->with(['success' => trans('auth/message.logout.success'), 'loggedout' => true]);
    }


    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'username' => 'required',
            'password' => 'required',
        ]);
    }


    public function username()
    {
        return 'username';
    }

    /**
     * Redirect the user after determining they are locked out.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function sendLockoutResponse(Request $request)
    {
        $seconds = $this->limiter()->availableIn(
            $this->throttleKey($request)
        );

        $minutes = round($seconds / 60);

        $message = \Lang::get('auth/message.throttle', ['minutes' => $minutes]);

        return redirect()->back()
            ->withInput($request->only($this->username(), 'remember'))
            ->withErrors([$this->username() => $message]);
    }


    /**
     * Override the lockout time and duration
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function hasTooManyLoginAttempts(Request $request)
    {
        $lockoutTime = config('auth.passwords.users.throttle.lockout_duration');
        $maxLoginAttempts = config('auth.passwords.users.throttle.max_attempts');

        return $this->limiter()->tooManyAttempts(
            $this->throttleKey($request),
            $maxLoginAttempts,
            $lockoutTime
        );
    }

    public function legacyAuthRedirect()
    {
        return redirect()->route('login');
    }

    public function redirectTo()
    {
        return Session::get('backUrl') ? Session::get('backUrl') : $this->redirectTo;
    }
>>>>>>> master
}
