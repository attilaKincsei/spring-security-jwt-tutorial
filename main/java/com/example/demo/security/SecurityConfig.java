package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * This class configures Spring Security.
 * By default Spring Security locks down all your endpoints and one must use HTTP Basic authentication to access anything,
 * we need to override this with our configuration.
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenServices jwtTokenServices;

    public SecurityConfig(JwtTokenServices jwtTokenServices) {
        this.jwtTokenServices = jwtTokenServices;
    }

    // By overriding this function and adding the @Bean annotation we can inject the AuthenticationManager into other classes.
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // The main point for configuring Spring Security.
    // In Spring Security every request goes trough a chain of filters; each filter checks the request for something
    // and if one fails the request will fail.
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .httpBasic().disable() // By default Spring Security uses HTTP Basic authentication, we disable this filter.
            .csrf().disable() // Disable CSRF. Leaving it enabled would ignore GET, HEAD, TRACE, OPTIONS
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Disable Tomcat's session management. This causes HttpSession to be null and no session cookie to be created
            .and()
                .authorizeRequests() // restrict access based on the config below:
                .antMatchers("/auth/signin").permitAll() // allowed by anyone
                .antMatchers(HttpMethod.GET, "/vehicles/**").authenticated() // allowed only when signed in
                .antMatchers(HttpMethod.DELETE, "/vehicles/**").hasRole("ADMIN") // allowed only if signed in and has ADMIN role
                .antMatchers(HttpMethod.GET, "/me").authenticated() // allowed only when signed in
                .anyRequest().denyAll() // anything else is denied; this is a safeguard in case we left something out.
            .and().formLogin().loginPage("/auth/signin")
            .and()
                .addFilterBefore(new JwtTokenFilter(jwtTokenServices), UsernamePasswordAuthenticationFilter.class); // Here we define our custom filter that uses the JWT tokens for authentication.
    }

}
