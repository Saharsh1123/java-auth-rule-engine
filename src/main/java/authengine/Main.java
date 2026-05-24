package authengine;

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