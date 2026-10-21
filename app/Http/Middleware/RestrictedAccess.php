<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * RestrictedAccess
 *
 * When RESTRICTED_INSTANCE (config: instance.restricted.enabled) is true, the
 * instance becomes fully private: no endpoint is reachable by an unauthenticated
 * visitor EXCEPT the allowlist below, which covers what is needed to sign up,
 * log in (incl. 2FA / login email verification), recover an account, and let
 * mobile apps discover the instance and authenticate.
 *
 * This middleware is registered on BOTH the `web` and `api` groups (see
 * bootstrap/app.php). Upstream only applies it to `web`, which leaves the
 * Mastodon-compatible API (public timelines, account lookups, search, ...)
 * readable by anonymous clients.
 *
 * A request is permitted when ANY of the following is true:
 *   1. Restricted mode is disabled.
 *   2. The user is authenticated (web session OR a valid API/Passport token).
 *   3. The request path matches an allowlisted pattern.
 *
 * Everything else is denied: API/JSON requests get a 401, web requests are
 * redirected to /login.
 *
 * NOTE: With restricted mode on, federation (inbox/outbox/actor delivery) and
 * all public content endpoints are intentionally blocked. To re-open specific
 * paths without editing this file, set RESTRICTED_INSTANCE_ALLOWED_PATHS
 * (config('instance.restricted.allowed_paths')).
 */
class RestrictedAccess
{
    /**
     * Path patterns (Request::is() syntax, '*' wildcard) that remain publicly
     * reachable while the instance is restricted.
     *
     * @var array<int, string>
     */
    protected $allowedRoutes = [
        // --- Session login / logout, 2FA + login email verification ---
        'login',
        'login/*',
        'logout',
        'i/confirm-email/*',

        // --- Password reset / email recovery ---
        'password/*',
        'auth/forgot/*',

        // --- Curated onboarding (has its own enable/disable config) ---
        'auth/sign_up',
        'auth/sign_up/*',

        // --- App-based email verification ---
        'i/app-email-verify',
        'i/app-email-resend',

        // --- Remote auth (Mastodon) + OIDC ---
        'auth/raw/mastodon/*',
        'auth/mastodon/*',
        'auth/oidc/*',

        // --- Parental-control + admin invite registration ---
        'auth/pci/*',
        'auth/invite/*',

        // --- OAuth: token issuance + authorize screen only ---
        'oauth/token',
        'oauth/authorize',

        // --- Mobile app discovery + auth API ---
        'api/v1/apps',
        'api/v1/instance',
        'api/v2/instance',
        'api/nodeinfo/2.0.json',
        '.well-known/*',

        // In-app registration + admin invite API (iarpfc/iar/iarc/iarer, invite/*)
        'api/v1.1/auth/*',
        // App email-code verification + onboarding
        'api/auth/*',

        // --- Operational ---
        'api/service/health-check',

        // --- Legal pages (linked from signup, often legally required) ---
        'site/terms',
        'site/privacy',
        'e/terms',
        'e/privacy',
    ];

    /**
     * Routes that are only allowed when open registration is enabled.
     *
     * @var array<int, string>
     */
    protected $registrationRoutes = [
        'register',
        'register/*',
    ];

    /**
     * Handle an incoming request.
     *
     * @param  Request  $request
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        if (! config('instance.restricted.enabled')) {
            return $next($request);
        }

        if ($this->isAuthenticated($guard)) {
            return $next($request);
        }

        if ($this->isPublicPath($request)) {
            return $next($request);
        }

        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'restricted_instance',
                'message' => 'This instance is private. Authentication is required.',
            ], 401);
        }

        return redirect('/login');
    }

    /**
     * Authenticated via the session (web) guard or a valid API/Passport token.
     */
    protected function isAuthenticated($guard = null): bool
    {
        if ($guard) {
            return Auth::guard($guard)->check();
        }

        return Auth::guard('web')->check() || Auth::guard('api')->check();
    }

    /**
     * Whether the request path is on the public allowlist.
     */
    protected function isPublicPath($request): bool
    {
        $patterns = $this->allowedRoutes;

        if (config('pixelfed.open_registration')) {
            $patterns = array_merge($patterns, $this->registrationRoutes);
        }

        $patterns = array_merge(
            $patterns,
            array_values((array) config('instance.restricted.allowed_paths', []))
        );

        return $request->is(...$patterns);
    }
}
