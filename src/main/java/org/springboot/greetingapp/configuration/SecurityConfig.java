package org.springboot.greetingapp.configuration;

import org.hibernate.annotations.ConcreteProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{

        httpSecurity
                .csrf(csrf -> csrf.disable())  // Disable CSRF protection
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll())  // Allow all requests
                .headers(headers -> headers.frameOptions(frame -> frame.disable())) // Allow frames (for H2 Console)
                .httpBasic(basic -> basic.disable())  // Disable Basic Auth
                .formLogin(form -> form.disable());  // Disable Login Form

        return httpSecurity.build();
    }

}
