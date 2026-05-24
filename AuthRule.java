interface AuthRule {
    AuthDecision evaluate(Request request);
}