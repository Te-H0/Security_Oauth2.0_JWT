package me.practice.Security_Oauth2._JWT.domain.test;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginDto {

    private String username;

    private String password;

    private String email;
}

