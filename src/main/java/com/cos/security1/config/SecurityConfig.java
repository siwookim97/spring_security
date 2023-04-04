package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터(이 클래스)가 스프링 필터체인에 등록
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf().disable().authorizeHttpRequests()
//                .requestMatchers("/user/**").authenticated()
//                .requestMatchers("/manager/**").hasAnyRole("ROLE_ADMIN", "ROLE_MANAGER")
//                .requestMatchers("/admin/**").hasRole("ROLE_ADMIN")
//                .anyRequest().permitAll() // 위 3개 말고는 다 허용
//                .and()
//                .formLogin()
//                .loginPage("/loginForm") // 권한이 없으면 login 페이지로
//                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행
//                .defaultSuccessUrl("/");

        http.csrf().disable()
               .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user/**").authenticated()
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll()
                )
                .formLogin()
                .loginPage("/loginForm") // 권한이 없으면 login 페이지로
                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요함.
                .userInfoEndpoint()
                .userService(principalOauth2UserService);
        // 1.코드받기(인증), 2.엑세스토큰(권한), 3.사용자 프로필정보를 가져오고 4-1.그 정보를 토대로 회원가입을 자동으로 진행가능
        // 4-2.구글이 가지고 있는 사용자 정보보다 모자라면 (ex.집주소)

        return http.build();
    }
}
