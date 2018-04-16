package org.cedardevs.saml_spike.configs

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml

@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Value('${security.saml2.metadata-url}')
    String metadataUrl

    @Value('${server.ssl.key-alias}')
    String keyAlias

    @Value('$[server.ssl.key-store-password}')
    String password

    @Value('${server.port}')
    String port

    @Value('${server.ssl.key-store')
    String keyStoreFilePath

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/saml/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .apply(saml())
                .serviceProvider()
                .keyStore()
                .storeFilePath("saml/keystore.jks")
                .password(password)
                .keyname(keyAlias)
                .and()
            .protocol("https")
                .hostname(String.format("%s:%s", "localhost", port))
                .basePath("/")
                .and()
            .identityProvider()
                .metadataFilePath(metadataUrl)
                .and()
    }
}