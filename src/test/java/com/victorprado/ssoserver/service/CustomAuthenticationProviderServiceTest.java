package com.victorprado.ssoserver.service;

import static org.assertj.core.api.BDDAssertions.then;
import static org.assertj.core.api.BDDAssertions.thenExceptionOfType;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

import java.util.Collections;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

class CustomAuthenticationProviderServiceTest {

  final CustomUserDetailsService customUserDetailsService = Mockito.mock(CustomUserDetailsService.class);
  final PasswordEncoder passwordEncoder = Mockito.mock(PasswordEncoder.class);
  final CustomAuthenticationProviderService service = new CustomAuthenticationProviderService(customUserDetailsService, passwordEncoder);

  @Test
  @DisplayName("Should return authentication token")
  void test1() {
    var user = getUser();
    given(customUserDetailsService.loadUserByUsername(anyString()))
      .willReturn(user);

    given(passwordEncoder.matches(anyString(), anyString()))
      .willReturn(true);

    var token = service.authenticate(new UsernamePasswordAuthenticationToken(new Object(), new Object(), Collections.emptyList()));
    then(token).isNotNull();
  }

  @Test
  @DisplayName("Should throw exception if password doesnt match")
  void test2() {
    var user = getUser();
    given(customUserDetailsService.loadUserByUsername(anyString()))
      .willReturn(user);

    given(passwordEncoder.matches(anyString(), anyString()))
      .willReturn(false);

    thenExceptionOfType(BadCredentialsException.class)
      .isThrownBy(() -> service.authenticate(new UsernamePasswordAuthenticationToken(new Object(), new Object(), Collections.emptyList())))
      .withMessage("Invalid username or password.");
  }

  @Test
  @DisplayName("Should return true if it supports the authentication type")
  void test3() {
    var supports = service.supports(UsernamePasswordAuthenticationToken.class);
    then(supports).isTrue();
  }

  private UserDetails getUser() {
    return User.builder()
      .username("a@a.com")
      .password("1234")
      .authorities(new SimpleGrantedAuthority("api.read"))
      .build();
  }
}
