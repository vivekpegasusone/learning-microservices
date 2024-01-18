package com.whizzy.rentcloud.authservice.service;

import com.whizzy.rentcloud.authservice.model.AuthUserDetail;
import com.whizzy.rentcloud.authservice.model.User;
import com.whizzy.rentcloud.authservice.repository.UserDetailRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Service("userDetailsService")
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private UserDetailRepository userRepo;

    private AccountStatusUserDetailsChecker checker = new AccountStatusUserDetailsChecker();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));

        Set<GrantedAuthority> authorities = new HashSet<>();
        user.getRoles().forEach(
                r -> {
                    authorities.add(new SimpleGrantedAuthority(r.getName()));
                    r.getPermissions().forEach(
                            p -> {
                                authorities.add(new SimpleGrantedAuthority(p.getName()));
                            }
                    );
                }
        );

        AuthUserDetail authUser = new AuthUserDetail(user, authorities);
        checker.check(authUser);

        return authUser;
    }
}
