package authengine;

public class ParseResult {
    boolean success;
    Request request;
    String errorMessage;
    
    ParseResult(boolean success, Request request, String errorMessage) {
        this.success = success;
        this.request = request;
        this.errorMessage = errorMessage;
    }
}