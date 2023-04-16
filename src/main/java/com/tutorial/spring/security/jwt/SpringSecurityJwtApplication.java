package com.tutorial.spring.security.jwt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@MapperScan(basePackageClasses = SpringSecurityJwtApplication.class)
@SpringBootApplication
public class SpringSecurityJwtApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringSecurityJwtApplication.class, args);
  }

  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

}
