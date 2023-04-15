package com.tutorial.spring.security.jwt.config.security;

import com.tutorial.spring.security.jwt.utils.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final JwtTokenProvider jwtTokenProvider;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .httpBasic().disable() // 基本設定を無効にする
        .csrf().disable() // CSRFを使用しない
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // セッションを使用しない
        .and()
        .authorizeRequests()
        .antMatchers("/*/login", "/*/join").permitAll()
        .anyRequest().hasRole("USER")
        .and()
        .exceptionHandling().accessDeniedHandler(new CustomAccessDeniedHandler())
        .and()
        .exceptionHandling().authenticationEntryPoint(new CustomAuthenticationEntryPoint())
        .and()
        .addFilterBefore(new JwtFilter(jwtTokenProvider),
            UsernamePasswordAuthenticationFilter.class); // ID, Password 検証前にJWTフィルタをかける
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web
        .ignoring()
        .antMatchers("/v2/api-docs", "/swagger-resources/**", "/swagger-ui.html", "/webjars/**",
            "/swagger/**"); // swaggerに関するリクエストは許可
  }
}
