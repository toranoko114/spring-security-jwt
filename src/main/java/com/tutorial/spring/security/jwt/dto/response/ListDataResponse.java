package com.tutorial.spring.security.jwt.dto.response;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ListDataResponse<T> extends BaseResponse {

  private List<T> data; // リスト形式のデータ
}
