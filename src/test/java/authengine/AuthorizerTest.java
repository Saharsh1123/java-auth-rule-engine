package authengine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuthorizerTest {

    private Request request(HttpMethod method, String path, Role role, String apiKey) {
        return new Request(method, path, role, apiKey);
    }

    private void assertDecision(AuthDecision decision, boolean expectedAllowed, String expectedReason) {
        assertEquals(expectedAllowed, decision.allowed);
        assertEquals(expectedReason, decision.reason);
    }

    @Test
    void rejectsCompletelyInvalidApiKey() {
        Request request = request(HttpMethod.GET, "/health", Role.USER, "badkey");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "invalid api key");
    }

    @Test
    void rejectsApiKeyWithInvalidPrefix() {
        Request request = request(HttpMethod.GET, "/profile", Role.USER, "sk_fake_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "invalid api key");
    }

    @Test
    void rejectsApiKeyThatIsTooShort() {
        Request request = request(HttpMethod.GET, "/profile", Role.USER, "sk_test_123");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "invalid api key");
    }

    @Test
    void acceptsValidTestApiKey() {
        Request request = request(HttpMethod.GET, "/profile", Role.USER, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, true, "request authorized");
    }

    @Test
    void acceptsValidLiveApiKey() {
        Request request = request(HttpMethod.GET, "/profile", Role.USER, "sk_live_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, true, "request authorized");
    }

    @Test
    void rejectsBadApiKeyBeforeAllowingHealthEndpoint() {
        Request request = request(HttpMethod.GET, "/health", Role.USER, "badkey");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "invalid api key");
    }

    @Test
    void allowsHealthEndpointWithValidApiKey() {
        Request request = request(HttpMethod.GET, "/health", Role.USER, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, true, "public health endpoint");
    }

    @Test
    void deniesUserFromAdminPath() {
        Request request = request(HttpMethod.GET, "/admin", Role.USER, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "admin role required");
    }

    @Test
    void deniesServiceFromAdminPath() {
        Request request = request(HttpMethod.GET, "/admin", Role.SERVICE, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "admin role required");
    }

    @Test
    void allowsAdminOnAdminPath() {
        Request request = request(HttpMethod.GET, "/admin", Role.ADMIN, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, true, "request authorized");
    }

    @Test
    void deniesUserDeleteRequest() {
        Request request = request(HttpMethod.DELETE, "/profile", Role.USER, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "admin role required for DELETE");
    }

    @Test
    void deniesServiceDeleteRequest() {
        Request request = request(HttpMethod.DELETE, "/profile", Role.SERVICE, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "admin role required for DELETE");
    }

    @Test
    void allowsAdminDeleteRequest() {
        Request request = request(HttpMethod.DELETE, "/profile", Role.ADMIN, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, true, "request authorized");
    }

    @Test
    void deniesUserFromInternalPath() {
        Request request = request(HttpMethod.GET, "/internal", Role.USER, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "service role required");
    }

    @Test
    void deniesAdminFromInternalPath() {
        Request request = request(HttpMethod.GET, "/internal", Role.ADMIN, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, false, "service role required");
    }

    @Test
    void allowsServiceOnInternalPath() {
        Request request = request(HttpMethod.GET, "/internal", Role.SERVICE, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, true, "request authorized");
    }

    @Test
    void allowsNormalUserGetRequest() {
        Request request = request(HttpMethod.GET, "/profile", Role.USER, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, true, "request authorized");
    }

    @Test
    void allowsNormalUserPostRequest() {
        Request request = request(HttpMethod.POST, "/profile", Role.USER, "sk_test_12345");

        AuthDecision decision = Authorizer.authorize(request);

        assertDecision(decision, true, "request authorized");
    }
}