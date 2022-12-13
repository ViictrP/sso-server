package com.victorprado.ssoserver.service;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class CustomAuthenticationProviderService implements AuthenticationProvider {

  private final CustomUserDetailsService service;
  private final PasswordEncoder encoder;

  public CustomAuthenticationProviderService(CustomUserDetailsService service,
    PasswordEncoder encoder) {
    this.service = service;
    this.encoder = encoder;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    var email = authentication.getName();
    var password = authentication.getCredentials().toString();
    var user = service.loadUserByUsername(email);
    return checkPassword(user, password);
  }

  private Authentication checkPassword(UserDetails user, String rawPassword) {
    if (encoder.matches(user.getPassword(), rawPassword)) {
      return new UsernamePasswordAuthenticationToken(
        user.getUsername(),
        user.getPassword(),
        user.getAuthorities()
      );
    }
    throw new BadCredentialsException("Invalid username or password.");
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
