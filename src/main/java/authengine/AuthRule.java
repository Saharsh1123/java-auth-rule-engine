package authengine;

interface AuthRule {
    AuthDecision evaluate(Request request);
}