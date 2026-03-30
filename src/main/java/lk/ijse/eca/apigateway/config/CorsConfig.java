package lk.ijse.eca.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
public class CorsConfig {
    @Bean
    public CorsWebFilter corsWebFilter(){
        CorsConfiguration corsConfig = new CorsConfiguration();

        // ඉඩ ලබා දෙන origin එක (localhost:3000)
        corsConfig.setAllowedOriginPatterns(Collections.singletonList("*"));
        corsConfig.setMaxAge(3600L); // Preflight response එක cache කිරීමට කාලය

        // ඉඩ ලබා දෙන Methods
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // ඉඩ ලබා දෙන Headers
        corsConfig.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin", "X-Logged-In-User"));

        // Credentials (Cookies/Auth headers) වලට ඉඩ දීම
        corsConfig.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }
}
