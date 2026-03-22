package lk.ijse.eca.apigateway.filter;

import lk.ijse.eca.apigateway.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
@Slf4j
@NullMarked
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getPath().toString();

        if(path.contains("/api/v1/users") ||
           path.contains("/api/v1/files/details") ||
           path.contains("/api/v1/files/preview")) {
            return chain.filter(exchange);
        }

        if (!exchange.getRequest().getHeaders().containsHeader("Authorization")) {
            log.error("Missing Authorization Header");
            return onError(exchange, "Authorization header is missing in your request");
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.error("Invalid Authorization header format");
            return onError(exchange, "Invalid Authorization header format. Expected; 'Bearer <token>'");
        }

        String token = authHeader.substring(7);

        try {

            jwtUtil.validateToken(token);

            String username = jwtUtil.extractUsername(token);

            ServerHttpRequest request = exchange.getRequest().mutate()
                    .header("X-Logged-In-User", username)
                    .build();

            return chain.filter(exchange.mutate().request(request).build());

        } catch (Exception e) {
            log.error("Invalid Token: {}", e.getMessage());
            return onError(exchange, "Invalid or Expired JWT Token");
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);

        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorResponse = String.format("{\"status\": %d, \"error\": \"%s\", \"message\": \"%s\"}",
                HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase(), message);

        DataBuffer buffer = response.bufferFactory().wrap(errorResponse.getBytes(StandardCharsets.UTF_8));

        return response.writeWith(Mono.just(buffer));
    }

}
