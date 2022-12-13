package com.victorprado.ssoserver.config;

import static org.springframework.security.config.Customizer.withDefaults;

import com.victorprado.ssoserver.service.CustomAuthenticationProviderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {

  private final CustomAuthenticationProviderService customAuthenticationProvider;

  public DefaultSecurityConfig(CustomAuthenticationProviderService service) {
    this.customAuthenticationProvider = service;
  }

  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeRequests(
      authorizedRequests ->
        authorizedRequests.anyRequest().authenticated()
    ).formLogin(withDefaults());
    return http.build();
  }

  @Autowired
  public void bindAuthenticationProvider(AuthenticationManagerBuilder builder) {
    builder.authenticationProvider(customAuthenticationProvider);
  }
}
