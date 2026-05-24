class AuthDecision {
    boolean allowed;
    String reason;

    AuthDecision(boolean allowed, String reason) {
        this.allowed = allowed;
        this.reason = reason;
    }
}