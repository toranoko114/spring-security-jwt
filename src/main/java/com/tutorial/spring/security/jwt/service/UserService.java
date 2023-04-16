package com.tutorial.spring.security.jwt.service;

import com.tutorial.spring.security.jwt.dto.LoginDto;
import com.tutorial.spring.security.jwt.dto.UserDto;
import com.tutorial.spring.security.jwt.exception.DuplicatedUsernameException;
import com.tutorial.spring.security.jwt.exception.LoginFailedException;
import com.tutorial.spring.security.jwt.exception.UserNotFoundException;
import com.tutorial.spring.security.jwt.mapper.UserMapper;
import com.tutorial.spring.security.jwt.utils.JwtTokenProvider;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

  private final UserMapper userMapper;
  private final JwtTokenProvider jwtTokenProvider;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @Transactional
  public UserDto join(UserDto userDto) {
    if (userMapper.findUserByUsername(userDto.getUsername()).isPresent()) {
      throw new DuplicatedUsernameException("ログイン済です.");
    }

    userDto.setPassword(bCryptPasswordEncoder.encode(userDto.getPassword()));
    userMapper.save(userDto);

    return userMapper.findUserByUsername(userDto.getUsername()).get();
  }

  public String login(LoginDto loginDto) {
    UserDto userDto = userMapper.findUserByUsername(loginDto.getUsername())
        .orElseThrow(() -> new LoginFailedException("無効なIDです."));

    if (!bCryptPasswordEncoder.matches(loginDto.getPassword(), userDto.getPassword())) {
      throw new LoginFailedException("無効なパスワードです.");
    }

    return jwtTokenProvider.createToken(userDto.getUserId(),
        Collections.singletonList(userDto.getRole()));
  }

  public UserDto findByUserId(Long userId) {
    return userMapper.findByUserId(userId)
        .orElseThrow(() -> new UserNotFoundException("存在しないユーザです."));
  }
}
