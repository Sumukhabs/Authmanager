package com.security.authmanager.security.service;

import com.security.authmanager.model.User;
import com.security.authmanager.repository.CustomUserDetailsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    CustomUserDetailsRepository userDetailsRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userDetailsRepository.fetchUserByUserName(username);
        if(user==null){
            throw new UsernameNotFoundException("User Not Found with username: " + username);
        }else {
            return UserDetailsImpl.build(user);
        }
    }
}
