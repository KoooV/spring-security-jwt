package com.kov.springsecurityjwt.filter;

import com.kov.springsecurityjwt.service.CustomUserDetailService;
import com.kov.springsecurityjwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    private final CustomUserDetailService customUserDetailService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);//тк jwt передается из заголовка Authorization формате(Bearer <token>) -> берем подстроку с 7 индекса
        String username = null;
        try {
            username = jwtService.getUsernameFromToken(token);
        } catch (IllegalAccessException e) {
            throw new IllegalAccessException(e);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {//Пользователь с таким токеном существует(жизненый цкил не истек + валидная подпись), пользователь уже аутентифицирован

        }
    }


}
