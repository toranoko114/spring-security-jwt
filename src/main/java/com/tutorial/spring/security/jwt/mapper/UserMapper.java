package com.tutorial.spring.security.jwt.mapper;

import com.tutorial.spring.security.jwt.dto.UserDto;
import java.util.Optional;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {
    Optional<UserDto> findUserByUsername(String username);
    Optional<UserDto> findByUserId(Long userId);
    void save(UserDto userDto);
}
