class AdminPathRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if (request.path.equals("/admin") && (request.role != Role.ADMIN)) {
            return new AuthDecision(false, "admin role required");
        }

        return null;
    }
}