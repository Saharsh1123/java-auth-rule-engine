class Authorizer {
    private static final AuthRule[] RULES = {
    new ApiKeyRule(),
    new HealthRule(),
    new AdminPathRule(),
    new DeleteRule(),
    new InternalRule()
};

    public static AuthDecision authorize(Request request) {
        AuthDecision decision;
        for (AuthRule rule : RULES) {
            decision = rule.evaluate(request);
            if (decision != null) {
                return decision;
            }
        }
        return new AuthDecision(true, "request authorized");
    }
}