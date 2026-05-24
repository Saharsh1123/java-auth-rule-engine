package authengine;

class InternalRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if (request.role != Role.SERVICE && request.path.equals("/internal")) {
            return new AuthDecision(false, "service role required");
        }

        return null;
    }
}