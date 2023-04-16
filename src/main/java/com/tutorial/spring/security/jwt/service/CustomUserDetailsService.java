package com.tutorial.spring.security.jwt.service;

import static java.lang.String.format;

import com.tutorial.spring.security.jwt.dto.UserDto;
import com.tutorial.spring.security.jwt.exception.UserNotFoundException;
import com.tutorial.spring.security.jwt.mapper.UserMapper;
import java.util.Collections;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

  private final UserMapper userMapper;

  @Override
  public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
    return userMapper.findByUserId(Long.valueOf(userId))
        .map(this::addAuthorities)
        .orElseThrow(() -> new UserNotFoundException(format("User: %s, not found", userId)));
  }

  private UserDto addAuthorities(UserDto userDto) {
    userDto.setAuthorities(
        Collections.singletonList(new SimpleGrantedAuthority(userDto.getRole())));

    return userDto;
  }
}
