package com.daniel.springbootessentials.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.log4j.Log4j2;

@Log4j2
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
 /* Configurado para exigir autenticação básica (HTTP Basic Authentication) para todas as solicitações*/
        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        log.info("Password enconded {}", passwordEncoder.encode("admin"));

        auth.inMemoryAuthentication()
                .withUser("Daniel")
                .password(passwordEncoder.encode("admin"))
                .roles("USER", "ADMIN")
                .and()
                .withUser("Biana")
                .password(passwordEncoder.encode("admin"))
                .roles("USER");
    }

}
