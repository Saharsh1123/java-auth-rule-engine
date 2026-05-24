package authengine;

public class RequestParser {
    public static ParseResult parse(String[] args) {
            if (args.length != 4) {
                return new ParseResult(false, null, "Usage: java Main <method> <path> <role> <apiKey>");
            }

            HttpMethod method;
            Role role;

            try {
                method = HttpMethod.valueOf(args[0]);
            } catch (IllegalArgumentException e) {
                return new ParseResult(false, null, "DENY: invalid method");
            }

            try {
                role = Role.valueOf(args[2]);
            } catch (IllegalArgumentException e) {
                return new ParseResult(false, null, "DENY: invalid role");
            }

            Request request = new Request(method, args[1], role, args[3]);

            return new ParseResult(true, request, null);
        }
}