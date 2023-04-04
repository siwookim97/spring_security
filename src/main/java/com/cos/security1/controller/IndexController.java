package com.cos.security1.controller;

import com.cos.security1.config.auto.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // Spring Security는 자기만의 스프링 시큐리티 세션
    @GetMapping("/test/login")
    @ResponseBody
    public String loginTest(Authentication authentication,  @AuthenticationPrincipal PrincipalDetails userDetails) {
        System.out.println("/test/login =============");
        // 원래 UserDetails로 다운캐스팅 해야 하지만 PrincipalDetails가 UserDetails를 상속받아서 가능
        PrincipalDetails principalDetails =  (PrincipalDetails) authentication.getPrincipal();

        System.out.println("authentication : " + principalDetails.getUser());
        System.out.println("userDetails : " + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String logintOauthTest(Authentication authentication, @AuthenticationPrincipal OAuth2User oAuth) {
        System.out.println("/test/login =============");
        // OAuth2로 로그인하면 Authentication이 Oauth2User로 캐스팅 해야함
        OAuth2User oAuth2User =  (OAuth2User) authentication.getPrincipal();

        // 두개가 모두 같다
        System.out.println("authentication : " + oAuth2User.getAttributes());
        System.out.println("oauth2User : " + oAuth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index() {
        // 머스테치 -> 기본폴더 src/main/resources/
        // 뷰리졸버 설정 : templates (prefix), .mustache (suffix)
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user); // 비밀번호가 1234가 되어서 시큐리티로 로그인 할 수 없음 -> 암호화 해야함

        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    @ResponseBody
    public String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('MANAGER') or hasRole('ADMIN')")
    @GetMapping("/data")
    @ResponseBody
    public String data() {
        return "데이터 정보";
    }

}
