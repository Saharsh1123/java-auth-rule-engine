package authengine;

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