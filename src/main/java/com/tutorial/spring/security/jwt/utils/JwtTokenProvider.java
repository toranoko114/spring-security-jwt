package com.tutorial.spring.security.jwt.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

  @Value("${jwt.secret}")
  private String secretKey;

  @Value("${jwt.token-validity-in-seconds}")
  private long tokenValidMillisecond;

  private final UserDetailsService userDetailsService;
  private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

  @PostConstruct
  protected void init() {
    secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes()); // SecretKey Base64でエンコード
  }

  // JWTトークン生成
  public String createToken(Long userId, List<String> roles) {
    Claims claims = Jwts.claims().setSubject(Long.toString(userId));
    claims.put("roles", roles);
    Date now = new Date();

    return Jwts.builder()
        .setClaims(claims)
        .setIssuedAt(now)
        .setExpiration(new Date(now.getTime() + tokenValidMillisecond)) // 토큰 만료일 설정
        .signWith(SignatureAlgorithm.HS256, secretKey) // 암호화
        .compact();
  }

  // JWTトークンから認証情報照会
  public Authentication getAuthentication(String token) {
    UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserId(token));

    return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
  }

  // ユーザー名抽出
  public String getUserId(String token) {
    return Jwts.parser()
        .setSigningKey(secretKey)
        .parseClaimsJws(token)
        .getBody()
        .getSubject();
  }

  // Request headerからtokenを取り出す
  public String resolveToken(HttpServletRequest request) {
    String token = request.getHeader("Authorization");

    // 가져온 Authorization Header 가 문자열이고, Bearer 로 시작해야 가져옴
    if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
      return token.substring(7);
    }

    return null;
  }

  // JWTトークン有効性チェック
  public boolean validateToken(String token) {
    try {
      Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);

      return !claims.getBody().getExpiration().before(new Date());
    } catch (SecurityException | MalformedJwtException | IllegalArgumentException exception) {
      logger.info("誤ったJwtトークンです.");
    } catch (ExpiredJwtException exception) {
      logger.info("有効期限切れのJwtトークンです.");
    } catch (UnsupportedJwtException exception) {
      logger.info("サポート外のJwtトークンです.");
    }

    return false;
  }
}
