package com.tutorial.spring.security.jwt.config.security;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import com.tutorial.spring.security.jwt.service.CustomUserDetailsService;
import com.tutorial.spring.security.jwt.utils.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JwtTokenProvider jwtTokenProvider;
  private final CustomUserDetailsService customUserDetailsService;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class)
        .userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder()).and()
        .build();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.httpBasic().disable() // 基本設定を無効にする
        .csrf().disable() // CSRFを使用しない
        .sessionManagement().sessionCreationPolicy(STATELESS) // セッションを使用しない
        .and().authorizeRequests().antMatchers("/*/login", "/*/join").permitAll().anyRequest()
        .hasRole("USER").and().exceptionHandling()
        .accessDeniedHandler(new CustomAccessDeniedHandler()).and().exceptionHandling()
        .authenticationEntryPoint(new CustomAuthenticationEntryPoint()).and()
        .addFilterBefore(new JwtFilter(jwtTokenProvider),
            UsernamePasswordAuthenticationFilter.class); // ID, Password 検証前にJWTフィルタをかける
    return http.build();
  }
}