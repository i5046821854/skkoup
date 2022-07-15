package com.skku_tinder.demo.service;

import com.skku_tinder.demo.domain.RefreshToken;
import com.skku_tinder.demo.domain.User;
import com.skku_tinder.demo.dto.LoginResDto;
import com.skku_tinder.demo.dto.SignupReqDto;
import com.skku_tinder.demo.dto.TokenDto;
import com.skku_tinder.demo.dto.TokenReqDto;
import com.skku_tinder.demo.exception.UserAuthException;
import com.skku_tinder.demo.repository.RefreshTokenJpaRepo;
import com.skku_tinder.demo.repository.UserRepository;
import com.skku_tinder.demo.security.JwtTokenProvider;
import com.skku_tinder.demo.security.kakao.KakaoOAuth2;
import com.skku_tinder.demo.security.kakao.KakaoUserInfo;
import org.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.Message;
import javax.mail.internet.MimeMessage;
import java.util.ArrayList;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
@Transactional
public class UserService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final KakaoOAuth2 kakaoOAuth2;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenJpaRepo refreshTokenJpaRepo;
    private final RedisTemplate<String, String> redisTemplate;
    private static final String ADMIN_TOKEN = "AAABnv/xRVklrnYxKZ0aHgTBcXukeZygoC";

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, KakaoOAuth2 kakaoOAuth2, AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, RefreshTokenJpaRepo refreshTokenJpaRepo, RedisTemplate<String, String> redisTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.kakaoOAuth2 = kakaoOAuth2;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenJpaRepo = refreshTokenJpaRepo;
        this.redisTemplate = redisTemplate;
    }

    //토큰 생성 메소드
    private TokenDto makeToken(User user)
    {
        TokenDto tokenDto = jwtTokenProvider.createToken(String.valueOf(user.getId()), user.getGrades());
        /* Redis 사용하지 않고 H2 DB에 RefreshToken 저장
        RefreshToken refreshToken = RefreshToken.builder()
                .key(user.getId())
                .token(tokenDto.getRefreshToken())
                .build();
        refreshTokenJpaRepo.save(refreshToken); */
        redisTemplate.opsForValue().set("RT:"+user.getId(), tokenDto.getRefreshToken(), tokenDto.getRefreshTokenExpireDate(), TimeUnit.MILLISECONDS);
        return tokenDto;
    }

    public void registerUser(SignupReqDto requestDto) {
        String username = requestDto.getUsername();
        // 회원 ID 중복 확인
        Optional<User> found = userRepository.findByUsername(username);
        if (found.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자 ID 가 존재합니다.");
        }

        // 패스워드 인코딩
        String password = passwordEncoder.encode(requestDto.getPassword());
        String email = requestDto.getEmail();
        // 사용자 ROLE 확인
        if (requestDto.isAdmin()) {
            if (!requestDto.getAdminToken().equals(ADMIN_TOKEN)) {
                throw new IllegalArgumentException("관리자 암호가 틀려 등록이 불가능합니다.");
            }
        }

        User user = new User(username, password, email);
        userRepository.save(user);
    }

    public TokenDto kakaoLogin(String authorizedCode) {
        // 카카오 OAuth2 를 통해 카카오 사용자 정보 조회
        KakaoUserInfo userInfo = null;
        try {
            userInfo = kakaoOAuth2.getUserInfo(authorizedCode);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        Long kakaoId = userInfo.getId();
        String nickname = userInfo.getNickname();
        String email = userInfo.getEmail();

        System.out.println("nickname: "+ nickname);
        String username = nickname;
        String password = kakaoId + ADMIN_TOKEN;
        // DB 에 중복된 Kakao Id 가 있는지 확인
        User kakaoUser = userRepository.findByKakaoId(kakaoId)
                .orElse(null);

        // 중복된 id가 없을 경우 회원가입
        if (kakaoUser == null) {    
            // 패스워드 인코딩
            String encodedPassword = passwordEncoder.encode(password);

            ArrayList<String> grades = new ArrayList<>();
            grades.add("ROLE_USER");

            kakaoUser = new User(nickname, encodedPassword, email, kakaoId, grades);
            userRepository.save(kakaoUser);
        }
        return makeToken(kakaoUser);
    }


    public Long signup(SignupReqDto signupReqDto){
        if(userRepository.findByUsername(signupReqDto.getUsername()).orElse(null) == null)
            return userRepository.save(signupReqDto.toEntity()).getId();
        else
            throw new IllegalArgumentException("중복된 사용자 ID 가 존재합니다.");
    }

    public TokenDto login(String username, String password){
        System.out.println(username + " " + password);
        User member = userRepository.findByUsername(username)
                .orElseThrow(() -> {throw new IllegalArgumentException("가입되지 않은 아이디입니다.");});
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }
        return makeToken(member);
    }


    //만료된 토큰 새로 발급받기

    public TokenDto reissue(TokenReqDto tokenReqDto) {
        if(!jwtTokenProvider.validateToken(tokenReqDto.getRefreshToken())){
            throw new IllegalArgumentException("refresh token 오류");
        }

        String accessTk = tokenReqDto.getAccessToken();
        Authentication authentication = jwtTokenProvider.getAuthentication(accessTk);
        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> {throw new IllegalArgumentException("Invalid refresh Token");});
        /* Redis 미 사용
        RefreshToken refreshToken = refreshTokenJpaRepo.findByKey(user.getId())
                .orElseThrow(() -> {throw new IllegalArgumentException("No refresh Token");});*/
        String refreshToken = redisTemplate.opsForValue().get("RT:" + user.getId());

        if(!refreshToken.equals(tokenReqDto.getRefreshToken())){
            throw new IllegalArgumentException("refresh token 불일치");
        }

        TokenDto newTk = jwtTokenProvider.createToken(String.valueOf(user.getId()), user.getGrades());
        /* Redis 미 사용
        RefreshToken updateRefreshTk = refreshToken.updateToken(newTk.getRefreshToken());
        refreshTokenJpaRepo.save(updateRefreshTk); */
        redisTemplate.opsForValue().set("RT:" + user.getId(), newTk.getRefreshToken(), newTk.getRefreshTokenExpireDate(), TimeUnit.MILLISECONDS);
        return newTk;
    }

    public String logout(String accessToken) {
        if(!jwtTokenProvider.validateToken(accessToken)){
            return "fail";
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        User user = userRepository.findByUsername(authentication.getName()).orElse(null);
        String userId = String.valueOf(user.getId());
        if(redisTemplate.opsForValue().get("RT:" + userId) != null)
        {
            redisTemplate.delete("RT:" + userId);
        }
        Long expiration = jwtTokenProvider.getExpiration(accessToken);
        redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);

        return "success";
    }

    //자동 로그인
    public TokenDto Autologin(String accessToken) {
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        User user = userRepository.findByUsername(authentication.getName()).orElse(null);
        if(jwtTokenProvider.validateToken(accessToken))
            return makeToken(user);
        else
        {
            String userId = String.valueOf(user.getId());
            String refreshToken = redisTemplate.opsForValue().get("RT:" + userId);
            if(refreshToken != null)
                return reissue(TokenReqDto.builder().refreshToken(refreshToken).accessToken(accessToken).build());
            else
                throw new UserAuthException("로그인 세션이 만료되었습니다");
        }
    }
}