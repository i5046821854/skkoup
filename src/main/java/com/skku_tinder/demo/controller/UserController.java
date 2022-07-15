package com.skku_tinder.demo.controller;

import com.google.gson.JsonObject;
import com.skku_tinder.demo.domain.User;
import com.skku_tinder.demo.dto.LoginResDto;
import com.skku_tinder.demo.dto.SignupReqDto;
import com.skku_tinder.demo.dto.TokenDto;
import com.skku_tinder.demo.dto.TokenReqDto;
import com.skku_tinder.demo.exception.UserAuthException;
import com.skku_tinder.demo.repository.UserRepository;
import com.skku_tinder.demo.security.JwtTokenProvider;
import com.skku_tinder.demo.service.EmailService;
import com.skku_tinder.demo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@RestController
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final UserService userService;
    private final EmailService emailService;

    //에러 처리 로직
    @ExceptionHandler(value = UserAuthException.class)
    public JSONObject controllerExceptionHanlder(Exception e)
    {
        JSONObject responseJson = new JSONObject();
        try {
            responseJson.put("message", e.getMessage());
            responseJson.put("code", 500);
        } catch (JSONException jsonException) {
            jsonException.printStackTrace();
        }
        return responseJson;
    }


    // 회원가입
    @PostMapping("/join")
    public String join(@RequestBody Map<String, String> user) {

        SignupReqDto signupReqDto = SignupReqDto.builder()
                .username(user.get("username"))
                .password(passwordEncoder.encode(user.get("password"))).build();

        Long userId = userService.signup(signupReqDto);
        JsonObject js = new JsonObject();
        js.addProperty("userId", userId);
        return js.toString();

    }

    @PostMapping("/emailAuth")
    public String sendEmail(@RequestBody Map<String, String> req)
    {
        String address = req.get("address");
        emailService.sendEmail(address);
        System.out.println(address);
        return "success";
    }

    @PostMapping("/checkAuth")
    public String checkAuth(@RequestBody Map<String, String> req)
    {
        String num = req.get("auth");
        String result = emailService.authValidate(num);
        return result;
    }


//    //로그아웃
//    @GetMapping("/logout")
//    public String logout(@RequestHeader(value="X-AUTH-TOKEN") String accessToken)
//    {
//        System.out.println("logout 실행, 토큰 : " +  accessToken);
//        return userService.logout(accessToken);
//    }

    // 로그인
    @PostMapping("/login")
    public TokenDto login(@RequestBody Map<String, String> user) {
        System.out.println("controller 시작");
        TokenDto tokenDto = userService.login(user.get("username"), user.get("password"));
        return tokenDto;
    }

    // 자동로그인
    @PostMapping("/autoLogin")
    public TokenDto autoLogin(@RequestHeader(value = "token") String token) {
        TokenDto tokenDto = userService.Autologin(token);
        return tokenDto;
    }



    @PostMapping("/reissue")
    public TokenDto reissue(@RequestBody Map<String, String> req)
    {

        TokenReqDto tokenReqDto = TokenReqDto.builder()
                .accessToken(req.get("accessToken"))
                .refreshToken(req.get("refreshToken"))
                .build();
        return userService.reissue(tokenReqDto);
    }

    //로그아웃
    @GetMapping("/temp")
    public String logout(@RequestHeader(value="X-AUTH-TOKEN") String accessToken)
    {
        System.out.println("logout 실행, 토큰 : " +  accessToken);
        return userService.logout(accessToken);
    }


    @GetMapping("/user")
    public String user(@RequestBody Map<String, String> user)
    {
        return "hello";
    }

}
