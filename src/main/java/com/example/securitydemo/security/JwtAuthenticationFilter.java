package com.example.securitydemo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
	@Value("${app.jwtSecret}")
	private String jwtSecret;

	@Override
	protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
		String jwtToken = getJwtFromRequest(httpServletRequest);

		if (jwtToken!=null) {
			try {
				Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(jwtToken);

				//OK, we can trust this JWT
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(getUsernameFromJWT(jwtToken), null, new ArrayList<>());
				SecurityContextHolder.getContext().setAuthentication(authentication);
			} catch (SignatureException e) {
				//don't trust the JWT!
			}
		}

		filterChain.doFilter(httpServletRequest, httpServletResponse);
	}

	private String getJwtFromRequest(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");

		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7, bearerToken.length());
		}

		return null;
	}

	private String getUsernameFromJWT(String token) {
		Claims claims = Jwts.parser()
				.setSigningKey(jwtSecret)
				.parseClaimsJws(token)
				.getBody();

		return claims.get("user", HashMap.class).get("username").toString();
	}
}
