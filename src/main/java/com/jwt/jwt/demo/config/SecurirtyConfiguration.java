package com.jwt.jwt.demo.config;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;



@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
public class SecurirtyConfiguration {

    //at startup spring will try to look for a bean type of eban security dilter chain

    private String[] whitelist={"login","/","register"};

    private final JWTAuthFilter jwtAuthFilter;

    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

       http
               .csrf((csrf)-> csrf.disable())
               .authorizeHttpRequests(auth-> auth
                       .requestMatchers(whitelist).permitAll()//even if you have a jwt you can access this routes
                       .anyRequest()
                       .authenticated()


               )
               .sessionManagement((session)->session
                       .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
               )
               .authenticationProvider(authenticationProvider)
               .formLogin(login->
                       login
                               .loginPage("/login")
                               .permitAll()
               )
               .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)//First filter
               .logout(logout->
                       logout.logoutUrl("/logout")
                               .logoutSuccessHandler((req,res,auth)-> SecurityContextHolder.clearContext())
               );





        return http.build();
    }

}
