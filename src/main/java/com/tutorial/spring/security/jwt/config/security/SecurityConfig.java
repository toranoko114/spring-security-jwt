package com.tutorial.spring.security.jwt.config.security;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import com.tutorial.spring.security.jwt.service.CustomUserDetailsService;
import com.tutorial.spring.security.jwt.utils.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JwtTokenProvider jwtTokenProvider;
  private final CustomUserDetailsService customUserDetailsService;
  private final CustomAccessDeniedHandler customAccessDeniedHandler;
  private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http)
      throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class)
        .userDetailsService(customUserDetailsService)
        .passwordEncoder(bCryptPasswordEncoder)
        .and()
        .build();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.cors().and().csrf().disable();
    http.sessionManagement().sessionCreationPolicy(STATELESS)
        .and().authorizeHttpRequests().requestMatchers("/*/join", "/*/login").permitAll()
        .anyRequest().hasRole("USER")
        .and().exceptionHandling().accessDeniedHandler(customAccessDeniedHandler)
        .authenticationEntryPoint(customAuthenticationEntryPoint)
        .and().addFilterBefore(new JwtFilter(jwtTokenProvider),
            UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }
}
