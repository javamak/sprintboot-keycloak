package com.mak.oauth2_demo;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

/**
 * SecurityConfig class configures security settings for the application, enabling security filters
 * and setting up OAuth2 login and logout behavior.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  /**
   * Configures the security filter chain for handling HTTP requests, OAuth2 login, and logout.
   *
   * @param http HttpSecurity object to define web-based security at the HTTP level
   * @return SecurityFilterChain for filtering and securing HTTP requests
   * @throws Exception in case of an error during configuration
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        // Configures authorization rules for different endpoints
        .authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers("/")
                    .permitAll() // Allows public access to the root URL
                    .requestMatchers("/menu")
                    .authenticated() // Requires authentication to access "/menu"
                    .requestMatchers("/admin/**")
                    .hasAuthority("ADMIN")
                    .anyRequest()
                    .authenticated() // Requires authentication for any other request
            )
        // Configures OAuth2 login settings
        .oauth2Login(
            oauth2 ->
                oauth2
                    .userInfoEndpoint(
                        userInfo -> {
                          userInfo.oidcUserService(this.oidcUserService());
                        })
                    .loginPage(
                        "/oauth2/authorization/keycloak") // Sets custom login page for OAuth2 with
                    // Keycloak
                    .defaultSuccessUrl("/menu", true) // Redirects to "/menu" after successful login
            )
        // Configures logout settings
        .logout(
            logout ->
                logout
                    .logoutSuccessUrl("/") // Redirects to the root URL on successful logout
                    .invalidateHttpSession(true) // Invalidates session to clear session data
                    .clearAuthentication(true) // Clears authentication details
                    .deleteCookies("JSESSIONID") // Deletes the session cookie
            );

    return http.build();
  }


//https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html
  private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
    final OidcUserService delegate = new OidcUserService();

    return (userRequest) -> {
      // Delegate to the default implementation for loading a user
      OidcUser oidcUser = delegate.loadUser(userRequest);

      OAuth2AccessToken accessToken = userRequest.getAccessToken();

      Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
//      List<String>  roles = userService.loadRoles(oidcUser.getUserInfo().getPreferredUsername());
//      for(String role : roles) {
//        mappedAuthorities.add(new SimpleGrantedAuthority(role));
//      }
      if ("testuser1".equals(oidcUser.getUserInfo().getPreferredUsername())) {

        mappedAuthorities.add(new SimpleGrantedAuthority("ADMIN"));
        mappedAuthorities.add(new SimpleGrantedAuthority("SUPER_ADMIN"));
      }

      // TODO
      // 1) Fetch the authority information from the protected resource using accessToken
      // 2) Map the authority information to one or more GrantedAuthority's and add it to
      // mappedAuthorities

      // 3) Create a copy of oidcUser but use the mappedAuthorities instead
      ClientRegistration.ProviderDetails providerDetails =
          userRequest.getClientRegistration().getProviderDetails();
      String userNameAttributeName =
          providerDetails.getUserInfoEndpoint().getUserNameAttributeName();
      if (StringUtils.hasText(userNameAttributeName)) {
        oidcUser =
            new DefaultOidcUser(
                mappedAuthorities,
                oidcUser.getIdToken(),
                oidcUser.getUserInfo(),
                userNameAttributeName);
      } else {
        oidcUser =
            new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
      }

      return oidcUser;
    };
  }
}
