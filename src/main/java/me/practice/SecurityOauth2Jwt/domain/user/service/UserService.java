package me.practice.SecurityOauth2Jwt.domain.user.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import me.practice.SecurityOauth2Jwt.domain.user.Repository.UserRepository;
import me.practice.SecurityOauth2Jwt.domain.user.Role;
import me.practice.SecurityOauth2Jwt.domain.user.User;
import me.practice.SecurityOauth2Jwt.domain.user.dto.UserSignUpDto;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(UserSignUpDto userSignUpDto) throws Exception {

        if (userRepository.findByEmail(userSignUpDto.getEmail()).isPresent()) {
            throw new Exception("이미 존재하는 이메일입니다.");
        }

        if (userRepository.findByNickname(userSignUpDto.getNickname()).isPresent()) {
            throw new Exception("이미 존재하는 닉네임입니다.");
        }

        User user = User.builder()
                .email(userSignUpDto.getEmail())
                .password(passwordEncoder.encode(userSignUpDto.getPassword()))
                .nickname(userSignUpDto.getNickname())
                .role(Role.USER)
                .build();


        userRepository.save(user);
    }
}
