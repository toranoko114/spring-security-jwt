package com.tutorial.spring.security.jwt.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class BaseResponse {

  private boolean success; // リクエスト成功の有無
  private String message; // 返信メッセージ
}
