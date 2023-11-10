package me.practice.SecurityOauth2Jwt.domain.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    GUEST("ROLE_GUEST"), USER("ROLE_USER"); //security에서 권한 코드에 ROLE_이 붙어야한다.

    private final String key;
}
