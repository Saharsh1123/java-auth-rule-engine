package authengine;

class DeleteRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if (request.method == HttpMethod.DELETE && (request.role != Role.ADMIN)) {
                return new AuthDecision(false, "admin role required for DELETE");
            }

            return null;
    }
}