package authengine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RequestParserTest {

    private void assertParseFailure(ParseResult result, String expectedErrorMessage) {
        assertFalse(result.success);
        assertNull(result.request);
        assertEquals(expectedErrorMessage, result.errorMessage);
    }

    private void assertParsedRequest(
            ParseResult result,
            HttpMethod expectedMethod,
            String expectedPath,
            Role expectedRole,
            String expectedApiKey
    ) {
        assertTrue(result.success);
        assertNotNull(result.request);
        assertNull(result.errorMessage);

        assertEquals(expectedMethod, result.request.method);
        assertEquals(expectedPath, result.request.path);
        assertEquals(expectedRole, result.request.role);
        assertEquals(expectedApiKey, result.request.apiKey);
    }

    @Test
    void rejectsMissingArguments() {
        String[] args = {};

        ParseResult result = RequestParser.parse(args);

        assertParseFailure(result, "Usage: java Main <method> <path> <role> <apiKey>");
    }

    @Test
    void rejectsTooFewArguments() {
        String[] args = {"GET", "/profile", "USER"};

        ParseResult result = RequestParser.parse(args);

        assertParseFailure(result, "Usage: java Main <method> <path> <role> <apiKey>");
    }

    @Test
    void rejectsTooManyArguments() {
        String[] args = {"GET", "/profile", "USER", "sk_test_12345", "extra"};

        ParseResult result = RequestParser.parse(args);

        assertParseFailure(result, "Usage: java Main <method> <path> <role> <apiKey>");
    }

    @Test
    void rejectsInvalidMethod() {
        String[] args = {"PATCH", "/profile", "USER", "sk_test_12345"};

        ParseResult result = RequestParser.parse(args);

        assertParseFailure(result, "DENY: invalid method");
    }

    @Test
    void rejectsInvalidRole() {
        String[] args = {"GET", "/profile", "GUEST", "sk_test_12345"};

        ParseResult result = RequestParser.parse(args);

        assertParseFailure(result, "DENY: invalid role");
    }

    @Test
    void rejectsInvalidMethodBeforeInvalidRole() {
        String[] args = {"PATCH", "/profile", "GUEST", "sk_test_12345"};

        ParseResult result = RequestParser.parse(args);

        assertParseFailure(result, "DENY: invalid method");
    }

    @Test
    void parsesUserGetRequest() {
        String[] args = {"GET", "/profile", "USER", "sk_test_12345"};

        ParseResult result = RequestParser.parse(args);

        assertParsedRequest(result, HttpMethod.GET, "/profile", Role.USER, "sk_test_12345");
    }

    @Test
    void parsesAdminPostRequest() {
        String[] args = {"POST", "/admin", "ADMIN", "sk_live_abcdef"};

        ParseResult result = RequestParser.parse(args);

        assertParsedRequest(result, HttpMethod.POST, "/admin", Role.ADMIN, "sk_live_abcdef");
    }

    @Test
    void parsesServiceDeleteRequest() {
        String[] args = {"DELETE", "/internal", "SERVICE", "sk_test_12345"};

        ParseResult result = RequestParser.parse(args);

        assertParsedRequest(result, HttpMethod.DELETE, "/internal", Role.SERVICE, "sk_test_12345");
    }

    @Test
    void preservesPathExactly() {
        String[] args = {"GET", "/admin/settings", "ADMIN", "sk_test_12345"};

        ParseResult result = RequestParser.parse(args);

        assertParsedRequest(result, HttpMethod.GET, "/admin/settings", Role.ADMIN, "sk_test_12345");
    }

    @Test
    void doesNotValidateApiKeyBecauseAuthorizationHandlesThat() {
        String[] args = {"GET", "/health", "USER", "badkey"};

        ParseResult result = RequestParser.parse(args);

        assertParsedRequest(result, HttpMethod.GET, "/health", Role.USER, "badkey");
    }
}