package com.victorprado.ssoserver.service;

import static org.assertj.core.api.BDDAssertions.then;
import static org.assertj.core.api.BDDAssertions.thenExceptionOfType;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

import com.victorprado.ssoserver.entity.User;
import com.victorprado.ssoserver.repository.UserRepository;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

class CustomUserDetailsServiceTest {

  final UserRepository repository = Mockito.mock(UserRepository.class);
  final CustomUserDetailsService service = new CustomUserDetailsService(repository);

  @Test
  @DisplayName("Should load user by username")
  void test1() {
    var email = "a@a.com";
    var password = "password";
    var user = getUser(email, password);
    given(repository.findByEmail(anyString())).willReturn(Optional.of(user));

    var found = service.loadUserByUsername(email);

    then(found.getUsername()).isEqualTo(email);
    then(found.getPassword()).isEqualTo(password);
  }

  @Test
  @DisplayName("Should throw exception if user doesnt exist")
  void test2() {
    given(repository.findByEmail(anyString())).willReturn(Optional.empty());

    thenExceptionOfType(UsernameNotFoundException.class)
      .isThrownBy(() -> service.loadUserByUsername(""))
      .withMessage("User not found!");
  }

  private static User getUser(String email, String password) {
    return User.builder()
      .email(email)
      .password(password)
      .build();
  }
}
