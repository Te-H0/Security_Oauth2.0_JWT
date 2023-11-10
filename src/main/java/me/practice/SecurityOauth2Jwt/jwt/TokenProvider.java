package me.practice.SecurityOauth2Jwt.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider implements InitializingBean {
    private static final String AUTHORITIES_KEY = "auth";
    private static final String EMAIL_CLAIM = "email";
    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
    private final String secret;
    private final long accessTokenExpirationPeriod;
    private Key key;

    public TokenProvider(@Value("${jwt.secret}") String secret, @Value("${jwt.expiration}") Long accessTokenExpirationPeriod) {
        this.secret = secret;
        this.accessTokenExpirationPeriod = accessTokenExpirationPeriod * 1000;
    }

    //bean이 생성이되고 주입을 받은 후에 secret값 Base64 Decode해서 key변수에 할당
    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * AccessToken 생성 메소드
     * Authentication 객체에 포함되어 있는 권한 정보들을 담은 토큰을 생성
     */
    public String createAccessToken(String email) {
        //claim 설정
        Claims claims = Jwts.claims();
        claims.put(EMAIL_CLAIM, email);
        //expire 시간 설정
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.accessTokenExpirationPeriod);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(now))
                .signWith(key, SignatureAlgorithm.HS512) // 사용할 암호화 알고리즘과 signature에 들어갈 secret값 세팅
                .setExpiration(validity)//해당 옵션 안넣으면 expire안함
                .compact();

    }

    /**
     * getAuthentication 필요한가????????????
     */

    //Token에 담겨있는 권한 정보를 이용해서 Autehntication 객체 리턴-> Token으로 클레임 만들고 이를 이용해 유저 객체를 만들어서 최종적으로 Authentication 객체 리턴
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        log.info("어디고1");
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        log.info("어디고2");
        User principal = new User(claims.getSubject(), "", authorities);
        log.info("어디고3");

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean isTokenValid(String token) {
        try {
            JWT.require(Algorithm.HMAC512(secret)).build().verify(token);
            return true;
        } catch (Exception e) {
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
            return false;
        }
    }
//        Date now = new Date();
//        return JWT.create() // JWT 토큰을 생성하는 빌더 반환
//                .withSubject(ACCESS_TOKEN_SUBJECT) // JWT의 Subject 지정 -> AccessToken이므로 AccessToken
//                .withExpiresAt(new Date(now.getTime() + accessTokenExpirationPeriod)) // 토큰 만료 시간 설정
//
//                //클레임으로는 저희는 email 하나만 사용합니다.
//                //추가적으로 식별자나, 이름 등의 정보를 더 추가하셔도 됩니다.
//                //추가하실 경우 .withClaim(클래임 이름, 클래임 값) 으로 설정해주시면 됩니다
//                .withClaim(EMAIL_CLAIM, email)
//                .sign(Algorithm.HMAC512(secretKey)); // HMAC512 알고리즘 사용, application-jwt.yml에서 지정한 secret 키로 암호화
//    }
}
