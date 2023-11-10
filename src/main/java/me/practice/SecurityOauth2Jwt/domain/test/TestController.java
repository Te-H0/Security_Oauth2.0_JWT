package me.practice.Security_Oauth2._JWT.domain.test;

import lombok.extern.slf4j.Slf4j;
import me.practice.Security_Oauth2._JWT.jwt.JwtFilter;
import me.practice.Security_Oauth2._JWT.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api")
public class TestController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;


    public TestController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<String> authorize(@RequestBody LoginDto loginDto) {
        log.info("들어오기는하냐");
        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!");
        System.out.println("loginDto = " + loginDto);
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        log.info("여기?1");
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.info("여기?2");
        String jwt = tokenProvider.createAccessToken(loginDto.getEmail());
        log.info("여기?3");
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
        log.info("여기?4");
        return new ResponseEntity<>(jwt, httpHeaders, HttpStatus.OK);
    }
}
