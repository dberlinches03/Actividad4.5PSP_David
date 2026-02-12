package agenda.seguridad;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;


public class Constans {

    // Spring Security
    public static final String LOGIN_URL = "/login";
    public static final String HEADER_AUTHORIZACION_KEY = "token";
    public static final String TOKEN_BEARER_PREFIX = "Bearer";

    public static final String USER = "aitor";
    public static final String PASS = "1234";
    // JWT
    public static final String SUPER_SECRETE_KEY = "ZnJhc2VzbGFyZ2FzcGFyYWNvbG9jYXJjb21vY2xhdmVlbnVucHJvamVjdG9kZWVtZXB\n" +
            "sb3BhcmFqd3Rjb25zcHJpbmdzZWN1cml0eQ==bWlwcnVlYmFkZWVqbXBsb3BhcmFiYXN\n" +
            "lNjQ=";
    public static final long TOKEN_EXPIRATION_TIME = 864_000_000; // 10 day

    public static Key getSigningKey(String secret) {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
