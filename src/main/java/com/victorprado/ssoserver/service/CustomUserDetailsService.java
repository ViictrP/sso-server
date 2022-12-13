package com.victorprado.ssoserver.service;

import com.victorprado.ssoserver.repository.UserRepository;
import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

  private final UserRepository repository;

  public CustomUserDetailsService(UserRepository repository) {
    this.repository = repository;
  }

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    var user = repository.findByEmail(email)
      .orElseThrow(() -> new UsernameNotFoundException("User not found!"));
    return new User(
      user.getEmail(),
      user.getPassword(),
      true,
      true,
      true,
      true,
      List.of(new SimpleGrantedAuthority("api.read"))
    );
  }
}
