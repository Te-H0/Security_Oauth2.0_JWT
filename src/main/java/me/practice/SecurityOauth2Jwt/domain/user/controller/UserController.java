package me.practice.SecurityOauth2Jwt.domain.user.controller;

import lombok.RequiredArgsConstructor;
import me.practice.SecurityOauth2Jwt.domain.user.dto.UserSignInDto;
import me.practice.SecurityOauth2Jwt.domain.user.dto.UserSignUpDto;
import me.practice.SecurityOauth2Jwt.domain.user.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    @Value("${jwt.header}")
    private String accessHeader;

    @PostMapping("/sign-up")
    public String signUp(@RequestBody UserSignUpDto userSignUpDto) throws Exception {
        userService.signUp(userSignUpDto);
        return "회원가입 성공";
    }

    @PostMapping("/sign-in")
    public ResponseEntity<String> signIn(@RequestBody UserSignInDto userSignInDto) throws Exception {
        String jwt = userService.signIn(userSignInDto);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(accessHeader, "Bearer " + jwt);

        return new ResponseEntity<>(jwt, httpHeaders, HttpStatus.OK);

    }

    @GetMapping("/jwt-test")
    public String jwtTest() {
        return "jwtTest 요청 성공";
    }
}
