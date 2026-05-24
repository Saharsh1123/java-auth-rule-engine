class ApiKeyRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if ((!request.apiKey.startsWith("sk_test_") && !request.apiKey.startsWith("sk_live_")) || request.apiKey.length() < 12) {
            return new AuthDecision(false, "invalid api key");
        }

        return null;
    }
}