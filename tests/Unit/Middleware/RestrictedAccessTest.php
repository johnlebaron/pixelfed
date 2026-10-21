<?php

namespace Tests\Unit\Middleware;

use App\Http\Middleware\RestrictedAccess;
use App\Models\User;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class RestrictedAccessTest extends TestCase
{
    protected function runMiddleware(Request $request)
    {
        $middleware = new RestrictedAccess;

        return $middleware->handle($request, function () {
            return response('PASSED', 200);
        });
    }

    protected function req(string $path, string $method = 'GET'): Request
    {
        return Request::create($path, $method);
    }

    #[Test]
    public function middleware_is_registered_on_web_and_api_groups()
    {
        $groups = $this->app['router']->getMiddlewareGroups();

        $this->assertContains('restricted', $groups['web']);
        $this->assertContains('restricted', $groups['api']);
    }

    #[Test]
    public function disabled_lets_everything_through()
    {
        config(['instance.restricted.enabled' => false]);

        $response = $this->runMiddleware($this->req('/discover'));

        $this->assertEquals('PASSED', $response->getContent());
    }

    #[Test]
    public function restricted_blocks_anonymous_web_request_with_redirect()
    {
        config(['instance.restricted.enabled' => true]);

        $response = $this->runMiddleware($this->req('/discover'));

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('/login', $response->headers->get('Location'));
    }

    #[Test]
    public function restricted_blocks_anonymous_api_request_with_401_json()
    {
        config(['instance.restricted.enabled' => true]);

        $response = $this->runMiddleware($this->req('/api/v1/instance/peers'));

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertStringContainsString('restricted_instance', $response->getContent());
    }

    #[Test]
    public function restricted_allows_authenticated_user()
    {
        config(['instance.restricted.enabled' => true]);

        // non-persisted user is enough for guard()->check() to return true
        $this->actingAs(new User);

        $response = $this->runMiddleware($this->req('/discover'));

        $this->assertEquals('PASSED', $response->getContent());
    }

    /**
     * @return array<string, array{0:string, 1?:string}>
     */
    public static function allowlistedPaths(): array
    {
        return [
            'session login' => ['/login'],
            'login post' => ['/login', 'POST'],
            'login 2fa' => ['/login/2fa', 'POST'],
            'login cancel' => ['/login/cancel'],
            'login verify continue' => ['/login/verify/continue'],
            'login verify resend' => ['/login/verify/resend', 'POST'],
            'login confirm email link' => ['/i/confirm-email/abc/def'],
            'logout' => ['/logout', 'POST'],
            'curated onboarding' => ['/auth/sign_up'],
            'curated onboarding step' => ['/auth/sign_up/confirm'],
            'password reset' => ['/password/reset'],
            'password email' => ['/password/email', 'POST'],
            'forgot email' => ['/auth/forgot/email'],
            'app email verify' => ['/i/app-email-verify'],
            'app email resend' => ['/i/app-email-resend'],
            'mastodon remote auth' => ['/auth/raw/mastodon/start'],
            'mastodon callback' => ['/auth/mastodon/callback'],
            'oidc' => ['/auth/oidc/start'],
            'parental invite' => ['/auth/pci/1/abc'],
            'admin invite landing' => ['/auth/invite/a/abc'],
            'oauth token' => ['/oauth/token', 'POST'],
            'oauth authorize' => ['/oauth/authorize'],
            'app registration api' => ['/api/v1/apps', 'POST'],
            'instance v1' => ['/api/v1/instance'],
            'instance v2' => ['/api/v2/instance'],
            'nodeinfo' => ['/api/nodeinfo/2.0.json'],
            'webfinger' => ['/.well-known/webfinger'],
            'in-app registration' => ['/api/v1.1/auth/iarpfc'],
            'admin invite api' => ['/api/v1.1/auth/invite/admin/ec', 'POST'],
            'app code verify' => ['/api/auth/app-code-verify', 'POST'],
            'health check' => ['/api/service/health-check'],
            'terms' => ['/site/terms'],
            'privacy' => ['/site/privacy'],
        ];
    }

    #[Test]
    #[DataProvider('allowlistedPaths')]
    public function restricted_allows_signup_and_login_paths_for_anonymous(string $path, string $method = 'GET')
    {
        config(['instance.restricted.enabled' => true]);

        $response = $this->runMiddleware($this->req($path, $method));

        $this->assertEquals(
            'PASSED',
            $response->getContent(),
            "Expected [$method $path] to be publicly reachable in restricted mode"
        );
    }

    /**
     * @return array<string, array{0:string}>
     */
    public static function blockedPaths(): array
    {
        return [
            'home' => ['/'],
            'discover' => ['/discover'],
            'public timeline' => ['/timeline/public'],
            'profile' => ['/dansup'],
            'post' => ['/p/abc123'],
            'public api timeline' => ['/api/v1/timelines/public'],
            'account lookup' => ['/api/v1/accounts/lookup'],
            'search api' => ['/api/v2/search'],
            'instance peers' => ['/api/v1/instance/peers'],
            'web-api config' => ['/api/v2/config'],
            'federation inbox' => ['/f/inbox'],
            'instance actor' => ['/i/actor'],
            'custom emojis' => ['/api/v1/custom_emojis'],
            'apps verify (needs auth)' => ['/api/v1/apps/verify_credentials'],
            'oauth tokens list' => ['/oauth/tokens'],
            'loginAs (removed upstream entry)' => ['/loginAs/1'],
        ];
    }

    #[Test]
    #[DataProvider('blockedPaths')]
    public function restricted_blocks_public_content_for_anonymous(string $path)
    {
        config(['instance.restricted.enabled' => true]);

        $response = $this->runMiddleware($this->req($path));

        $this->assertContains(
            $response->getStatusCode(),
            [302, 401],
            "Expected [$path] to be blocked in restricted mode"
        );
        $this->assertNotEquals('PASSED', $response->getContent());
    }

    #[Test]
    public function register_is_blocked_when_open_registration_is_off()
    {
        config([
            'instance.restricted.enabled' => true,
            'pixelfed.open_registration' => false,
        ]);

        $response = $this->runMiddleware($this->req('/register'));

        $this->assertEquals(302, $response->getStatusCode());
    }

    #[Test]
    public function register_is_allowed_when_open_registration_is_on()
    {
        config([
            'instance.restricted.enabled' => true,
            'pixelfed.open_registration' => true,
        ]);

        $response = $this->runMiddleware($this->req('/register'));

        $this->assertEquals('PASSED', $response->getContent());
    }

    #[Test]
    public function config_allowed_paths_extends_allowlist()
    {
        config([
            'instance.restricted.enabled' => true,
            'instance.restricted.allowed_paths' => ['custom/public/*'],
        ]);

        $response = $this->runMiddleware($this->req('/custom/public/page'));

        $this->assertEquals('PASSED', $response->getContent());
    }
}
