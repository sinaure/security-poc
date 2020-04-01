package org.sinaure.instantsecurity.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.admin.client.Keycloak;
import org.sinaure.instantsecurity.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * SecurityConfigurer is to configure ResourceServer and HTTP Security.
 * <p>
 *   Please make sure you check HTTP Security configuration and change is as per your needs.
 * </p>
 *
 * Note: Use {@link SecurityProperties} to configure required CORs configuration and enable or disable security of application.
 */
@Configuration
@EnableWebSecurity
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
@ConditionalOnProperty(prefix = "rest.security", value = "enabled", havingValue = "true")
@Import({SecurityProperties.class})
public class SecurityConfigurer extends ResourceServerConfigurerAdapter {

  private ResourceServerProperties resourceServerProperties;

  private SecurityProperties securityProperties;

  /* Using spring constructor injection, @Autowired is implicit */
  public SecurityConfigurer(ResourceServerProperties resourceServerProperties, SecurityProperties securityProperties) {
    this.resourceServerProperties = resourceServerProperties;
    this.securityProperties = securityProperties;
  }

  @Autowired
  private AuthService authService;

  @Override
  public void configure(ResourceServerSecurityConfigurer resources){
    resources.resourceId(resourceServerProperties.getResourceId());
  }


  @Override
  public void configure(final HttpSecurity http) throws Exception {

    http.cors()
        .configurationSource(corsConfigurationSource())
        .and()
        .headers()
        .frameOptions()
        .disable()
        .and()
        .csrf()
        .disable()
        .authorizeRequests()
            .antMatchers("/api/v1/instant*")
            .hasAnyAuthority("ROLE_SUPERADMIN")
            .antMatchers("/api/v1/app*")
            .hasAnyAuthority("ROLE_USER")
            .anyRequest()
            .permitAll();

  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    if (null != securityProperties.getCorsConfiguration()) {
      source.registerCorsConfiguration("/**", securityProperties.getCorsConfiguration());
    }
    return source;
  }

  @Bean
  public JwtAccessTokenCustomizer jwtAccessTokenCustomizer(ObjectMapper mapper) {
    return new JwtAccessTokenCustomizer(mapper);
  }

  @Bean(name = "kc")
  public Keycloak keycloakAdmin(){
    String localhost = "http://localhost:8081";
    String client_id = "admin-cli";
    String admin = "keycloak";
    String admin_password = "9vJaTwrJnKS6";
    String realm = "master";
    return  authService.getKeycloakUser(localhost, realm, client_id, admin, admin_password);
  }
  @Bean(name = "kc_lime")
  public Keycloak keycloakLime(){
    String localhost = "http://localhost:8081";
    String client_id = "lime";
    String secret = "d686dc95-c1b9-4758-9036-e433e3ecb860";
    String realm = "lime";
    return  authService.getKeycloakClient(localhost, realm, client_id, secret);
  }
}
