package com.jwt.jwt.demo.config;

import com.jwt.jwt.demo.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//We just need spring to create a bean of this class

@Component
@RequiredArgsConstructor
public class JWTAuthFilter extends OncePerRequestFilter {



    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;



    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain filterChain) throws ServletException, IOException {
        //We can intercep request and send responses base on our filter

        final String authHeader=request.getHeader("Authorization");
        //We we make a call, we need to pass the token within the header

        final String jwt;

        final String userEmail;

        //We check for the token in therequest header
        if(authHeader==null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request,response);//we pass the request and response to the next filter
            return;
        }

        //We retrieve the token, the index is seven bc bearer has 6 letters
        jwt= authHeader.substring(7);

        userEmail= jwtService.extractUserName(jwt);//para sacar el email del token, nececitamos leer el token, y para eso nececitamos desencriptarlo


        if (userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null){

            //Si tenemos el mail del usuario, y no esta authenticado, buscamos su mail en la base de datos

            UserDetails userDetails=this.userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt,userDetails)){
                //cheqeuamos que el token sea valido
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);//This calls the next filter, if any, on the chain
    }
}
