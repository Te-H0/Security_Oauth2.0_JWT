package me.practice.SecurityOauth2Jwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Optional;

/**
 * Jwt 인증 필터
 * "/login" 이외의 URI 요청이 왔을 때 처리하는 필터
 * <p>
 * 기본적으로 사용자는 요청 헤더에 AccessToken만 담아서 요청
 * AccessToken 만료 시에만 RefreshToken을 요청 헤더에 AccessToken과 함께 요청
 * <p>
 * 1. RefreshToken이 없고, AccessToken이 유효한 경우 -> 인증 성공 처리, RefreshToken을 재발급하지는 않는다.
 * 2. RefreshToken이 없고, AccessToken이 없거나 유효하지 않은 경우 -> 인증 실패 처리, 403 ERROR
 * 3. RefreshToken이 있는 경우 -> DB의 RefreshToken과 비교하여 일치하면 AccessToken 재발급, RefreshToken 재발급(RTR 방식)
 * 인증 성공 처리는 하지 않고 실패 처리
 */

@Slf4j
public class JwtFilter extends GenericFilterBean {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    private final TokenProvider tokenProvider;
    @Value("${jwt.header}")
    private String accessHeader;

    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    //토큰의 인증정보를 SecurityContext에 저장하는 역할
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        log.info("요청 uri => {}", httpServletRequest.getRequestURI());
        log.info("진짜 여기지");
        log.info("jwt!!!!!!!=>{}", (httpServletRequest.getHeader("Content-Type")));
        String jwt = String.valueOf(extractAccessToken(httpServletRequest));

        log.info("filter error 1");
        String requestURI = httpServletRequest.getRequestURI();
        log.info("filter error 2");
        if (StringUtils.hasText(jwt) && tokenProvider.isTokenValid(jwt)) {
            log.info("filter error 3");
            Authentication authentication = tokenProvider.getAuthentication(jwt);//토큰이 정상적이면 authentication 받아옴
            SecurityContextHolder.getContext().setAuthentication(authentication);// 받아온 authentication 을 securityContext 에 저장
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    public Optional<String> extractAccessToken(HttpServletRequest request) {
        log.info("이거니?");
        String bearerToken = request.getHeader(accessHeader);
        log.info("headr => {}", bearerToken);
        return Optional.ofNullable(request.getHeader(accessHeader));

    }
    //-------------------------------------------------------------------------------------------------------------------------
//    private static final String NO_CHECK_URL = "/login"; // "/login"으로 들어오는 요청은 Filter 작동 X
//    private final JwtService jwtService;
//    private final UserRepository userRepository;
//    private TokenProvider tokenProvider;
//
//    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
//
//
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        if (request.getRequestURI().equals(NO_CHECK_URL)) {
//            filterChain.doFilter(request, response); // "/login" 요청이 들어오면, 다음 필터 호출
//            return; // return으로 이후 현재 필터 진행 막기 (안해주면 아래로 내려가서 계속 필터 진행시킴)
//        }
//
//        // 사용자 요청 헤더에서 RefreshToken 추출
//        // -> RefreshToken이 없거나 유효하지 않다면(DB에 저장된 RefreshToken과 다르다면) null을 반환
//        // 사용자의 요청 헤더에 RefreshToken이 있는 경우는, AccessToken이 만료되어 요청한 경우밖에 없다.
//        // 따라서, 위의 경우를 제외하면 추출한 refreshToken은 모두 null
////        String refreshToken = jwtService.extractRefreshToken(request)
////                .filter(jwtService::isTokenValid)
////                .orElse(null);
//
//        // 리프레시 토큰이 요청 헤더에 존재했다면, 사용자가 AccessToken이 만료되어서
//        // RefreshToken까지 보낸 것이므로 리프레시 토큰이 DB의 리프레시 토큰과 일치하는지 판단 후,
//        // 일치한다면 AccessToken을 재발급해준다.
////        if (refreshToken != null) {
////            checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
////            return; // RefreshToken을 보낸 경우에는 AccessToken을 재발급 하고 인증 처리는 하지 않게 하기위해 바로 return으로 필터 진행 막기
////        }
//
//        // RefreshToken이 없거나 유효하지 않다면, AccessToken을 검사하고 인증을 처리하는 로직 수행
//        // AccessToken이 없거나 유효하지 않다면, 인증 객체가 담기지 않은 상태로 다음 필터로 넘어가기 때문에 403 에러 발생
//        // AccessToken이 유효하다면, 인증 객체가 담긴 상태로 다음 필터로 넘어가기 때문에 인증 성공
////        if (refreshToken == null) {
////            checkAccessTokenAndAuthentication(request, response, filterChain);
////        }
//        checkAccessTokenAndAuthentication(request, response, filterChain);
//    }
//
//    /**
//     * [리프레시 토큰으로 유저 정보 찾기 & 액세스 토큰/리프레시 토큰 재발급 메소드]
//     * 파라미터로 들어온 헤더에서 추출한 리프레시 토큰으로 DB에서 유저를 찾고, 해당 유저가 있다면
//     * JwtService.createAccessToken()으로 AccessToken 생성,
//     * reIssueRefreshToken()로 리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드 호출
//     * 그 후 JwtService.sendAccessTokenAndRefreshToken()으로 응답 헤더에 보내기
//     */
////    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
////        userRepository.findByRefreshToken(refreshToken)
////                .ifPresent(user -> {
////                    String reIssuedRefreshToken = reIssueRefreshToken(user);
////                    jwtService.sendAccessAndRefreshToken(response, jwtService.createAccessToken(user.getEmail()),
////                            reIssuedRefreshToken);
////                });
////    }
//
//    /**
//     * [리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드]
//     * jwtService.createRefreshToken()으로 리프레시 토큰 재발급 후
//     * DB에 재발급한 리프레시 토큰 업데이트 후 Flush
//     */
////    private String reIssueRefreshToken(User user) {
////        String reIssuedRefreshToken = jwtService.createRefreshToken();
////        user.updateRefreshToken(reIssuedRefreshToken);
////        userRepository.saveAndFlush(user);
////        return reIssuedRefreshToken;
////    }
//
//    /**
//     * [액세스 토큰 체크 & 인증 처리 메소드]
//     * request에서 extractAccessToken()으로 액세스 토큰 추출 후, isTokenValid()로 유효한 토큰인지 검증
//     * 유효한 토큰이면, 액세스 토큰에서 extractEmail로 Email을 추출한 후 findByEmail()로 해당 이메일을 사용하는 유저 객체 반환
//     * 그 유저 객체를 saveAuthentication()으로 인증 처리하여
//     * 인증 허가 처리된 객체를 SecurityContextHolder에 담기
//     * 그 후 다음 인증 필터로 진행
//     */
//    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response,
//                                                  FilterChain filterChain) throws ServletException, IOException {
//        log.info("checkAccessTokenAndAuthentication() 호출");
//        jwtService.extractAccessToken(request)
//                .filter(jwtService::isTokenValid)
//                .ifPresent(accessToken -> jwtService.extractEmail(accessToken)
//                        .ifPresent(email -> userRepository.findByEmail(email)
//                                .ifPresent(this::saveAuthentication)));
//
//        filterChain.doFilter(request, response);
//    }
//
//    /**
//     * [인증 허가 메소드]
//     * 파라미터의 유저 : 우리가 만든 회원 객체 / 빌더의 유저 : UserDetails의 User 객체
//     * <p>
//     * new UsernamePasswordAuthenticationToken()로 인증 객체인 Authentication 객체 생성
//     * UsernamePasswordAuthenticationToken의 파라미터
//     * 1. 위에서 만든 UserDetailsUser 객체 (유저 정보)
//     * 2. credential(보통 비밀번호로, 인증 시에는 보통 null로 제거)
//     * 3. Collection < ? extends GrantedAuthority>로,
//     * UserDetails의 User 객체 안에 Set<GrantedAuthority> authorities이 있어서 getter로 호출한 후에,
//     * new NullAuthoritiesMapper()로 GrantedAuthoritiesMapper 객체를 생성하고 mapAuthorities()에 담기
//     * <p>
//     * SecurityContextHolder.getContext()로 SecurityContext를 꺼낸 후,
//     * setAuthentication()을 이용하여 위에서 만든 Authentication 객체에 대한 인증 허가 처리
//     */
//    public void saveAuthentication(User myUser) {
//        String password = myUser.getPassword();
//        if (password == null) { // 소셜 로그인 유저의 비밀번호 임의로 설정 하여 소셜 로그인 유저도 인증 되도록 설정
//            password = PasswordUtil.generateRandomPassword();
//        }
//
//        UserDetails userDetailsUser = org.springframework.security.core.userdetails.User.builder()
//                .username(myUser.getEmail())
//                .password(password)
//                .roles(myUser.getRole().name())
//                .build();
//
//        Authentication authentication =
//                new UsernamePasswordAuthenticationToken(userDetailsUser, null,
//                        authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//    }
}