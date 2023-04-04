package com.cos.security1.config.auto;

import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

// 시큐리티가 /login 을 주소 요청이 오면 낚아채서 로그인을 진행시킴
// 로그인 진행이 완료가 되면 session 을 만들어준다. (Security ContextHolder 에다가 session)
// Authentication 타입의 객체만 들어갈 수 있다
// Authentication 안에 User 정보가 있어야 된다.
// User 객체타입 -> UserDetails 타입 객체

// Security Session -> Authentication -> UserDetails (User 객체에 접근 가능)

@Data
public class PrincipalDetails implements UserDetails {

    private User user; // 컴포지션

    public PrincipalDetails(User user) {
        this.user = user;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        // 계정이 사이트에서 1년동안 회원이 로그인을 안하면 휴먼 계정으로 전환해야 한다.
        // 현재시간 - 로그인 시간 -> 1년 초과하면 return false;
        // user.getLoginDate(); 로그인 시간을 가져와서

        return true;
    }

    // 해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(() -> {
            return user.getRole();
        });
        return collect;
    }
}
