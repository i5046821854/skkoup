package com.skku_tinder.demo.service;

import com.skku_tinder.demo.repository.RefreshTokenJpaRepo;
import com.skku_tinder.demo.repository.UserRepository;
import com.skku_tinder.demo.security.JwtTokenProvider;
import com.skku_tinder.demo.security.kakao.KakaoOAuth2;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.Message;
import javax.mail.internet.MimeMessage;
import java.sql.Time;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
@Transactional
@RequiredArgsConstructor
public class EmailService {

    private final RedisTemplate<String, String> redisTemplate;
    private final JavaMailSender javaMailSender;
    private final long mailAuthValidTime = 1000 * 60 * 5L;



    public String createCode()
    {
        Random random = new Random();
        String key = "";
        for(int i = 0; i< 3; i++)
            key += String.valueOf(random.nextInt(100));
        key += (char) ((int) (random.nextInt(26)) + 97);
        for(int i = 0; i< 3; i++)
            key += String.valueOf(random.nextInt(100));
        key += (char) ((int) (random.nextInt(26)) + 65);

        return key;
    }
    public MimeMessage createMessage(String to, String code) throws Exception{
        MimeMessage message = javaMailSender.createMimeMessage();
        message.addRecipients(Message.RecipientType.TO, to);
        message.setSubject("인증문자 발송");
        String content = "인증문자는 " + code + " 입니다.";
        message.setText(content, "utf-8", "html");
        message.setFrom("o5046821854@gmail.com");
        System.out.println(content);
        return message;
    }

    @Async
    public void sendEmail(String address) {
        try {
            String code = createCode();
            MimeMessage message = createMessage(address, code);
            javaMailSender.send(message);
            redisTemplate.opsForValue().set(code, address, mailAuthValidTime, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String authValidate(String num) {
        if(redisTemplate.opsForValue().get(num) != null)
        {
            return "success";
        }
        return "fail";
    }
}
