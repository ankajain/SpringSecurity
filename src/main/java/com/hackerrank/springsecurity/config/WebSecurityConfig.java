package com.hackerrank.springsecurity.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(
        final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("john_doe")
            .password("{noop}student_password")
            .authorities("ROLE_STUDENT_USER")
            .and()
            .withUser("jane_doe")
            .password("{noop}admin_password")
            .authorities("ROLE_OFFICE_ADMIN");
    }

    @Override
    protected void configure(
        final HttpSecurity http) throws Exception {
        http.csrf()
            .disable();
        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests()
            .antMatchers("/student**")
            .hasAnyAuthority("ROLE_STUDENT_USER", "ROLE_OFFICE_ADMIN")
            .antMatchers("/course**")
            .hasAnyAuthority("ROLE_OFFICE_ADMIN")
            .anyRequest()
            .authenticated()
            .and()
            .httpBasic();
                http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
        ;

    }

    private AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint();
    }

    @Override
    public void configure(
        final WebSecurity web) throws Exception {
        web.ignoring()
            .antMatchers(HttpMethod.GET, "/**");
    }
}

class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        Map<String, Object> data = new HashMap<>();
        data.put("message", "Authentication Failure-The user name and password combination is incorrect");

        OutputStream out = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(out, data);
        out.flush();
    }
}