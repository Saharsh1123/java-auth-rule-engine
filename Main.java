public class Main {
    public static void main(String[] args) {
        if (args.length != 4) {
            System.out.println("Usage: java Main <method> <path> <role> <apiKey>");
            return;
        }

        HttpMethod method;
        Role role;

        try {
            method = HttpMethod.valueOf(args[0]);
        } catch (IllegalArgumentException e) {
            System.out.println("DENY: invalid method");
            return;
        }

        try {
            role = Role.valueOf(args[2]);
        } catch (IllegalArgumentException e) {
            System.out.println("DENY: invalid role");
            return;
        }

        Request request = new Request(method, args[1], role, args[3]);
        AuthDecision decision = Authorizer.authorize(request);
        String access = "DENY";

        if (decision.allowed) {
            access = "ALLOW";
        } 
        System.out.println("%s: %s".formatted(access, decision.reason));
    }
}

enum Role {
    USER,
    ADMIN,
    SERVICE
}

enum HttpMethod {
    GET,
    POST,
    DELETE
}

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


interface AuthRule {
    AuthDecision evaluate(Request request);
}

class ApiKeyRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if ((!request.apiKey.startsWith("sk_test_") && !request.apiKey.startsWith("sk_live_")) || request.apiKey.length() < 12) {
            return new AuthDecision(false, "invalid api key");
        }

        return null;
    }
}

class HealthRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if (request.path.equals("/health")) {
            return new AuthDecision(true, "public health endpoint");
        }

        return null;
    }
}   

class DeleteRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if (request.method == HttpMethod.DELETE && (request.role != Role.ADMIN)) {
                return new AuthDecision(false, "admin role required for DELETE");
            }

            return null;
    }
}

class AdminPathRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if (request.path.equals("/admin") && (request.role != Role.ADMIN)) {
            return new AuthDecision(false, "admin role required");
        }

        return null;
    }
}

class InternalRule implements AuthRule {
    public AuthDecision evaluate(Request request) {
        if (request.role != Role.SERVICE && request.path.equals("/internal")) {
            return new AuthDecision(false, "service role required");
        }

        return null;
    }
}

class Request {
    HttpMethod method;
    String path;
    Role role;
    String apiKey;

    Request(HttpMethod method, String path, Role role, String apiKey) {
        this.method = method;
        this.path = path;
        this.role = role;
        this.apiKey = apiKey;
    }
}

class AuthDecision {
    boolean allowed;
    String reason;

    AuthDecision(boolean allowed, String reason) {
        this.allowed = allowed;
        this.reason = reason;
    }
}