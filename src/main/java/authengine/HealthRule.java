package authengine;

class HealthRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if (request.path.equals("/health")) {
            return new AuthDecision(true, "public health endpoint");
        }

        return null;
    }
}   