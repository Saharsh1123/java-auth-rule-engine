package authengine;

public class Main {
    public static void main(String[] args) {
        ParseResult result = RequestParser.parse(args);
        
        if (result.success == false) {
            System.out.println(result.errorMessage);
        }

        AuthDecision decision = Authorizer.authorize(result.request);
        String access = "DENY";

        if (decision.allowed) {
            access = "ALLOW";
        } 

        System.out.println("%s: %s".formatted(access, decision.reason));
    }
}