package com.example.securitydemo.config;

import com.example.securitydemo.security.CustomUserDetailService;
import com.example.securitydemo.security.JwtAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@EnableWebSecurity
public class AppSecurity extends WebSecurityConfigurerAdapter{
	@Value("${app.jwtSecret}")
	private String jwtSecret;

	@Value("${app.jwtExpirationInMs}")
	private int jwtExpirationInMs;

	@Autowired
	private AuthenticationEntryPoint unAuthorizedHandler;

	@Autowired
	private CustomUserDetailService customUserDetailService;

	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter() {
		return new JwtAuthenticationFilter();
	}

	@Autowired
	private PasswordEncoder bCryptPasswordEncoder;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	public AppSecurity(CustomUserDetailService customUserDetailService) {
		this.customUserDetailService = customUserDetailService;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors()
				.and()
				.csrf().disable()
				.exceptionHandling().authenticationEntryPoint(unAuthorizedHandler)
				.and()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.authorizeRequests()
				.anyRequest().authenticated()
				.and()
				.formLogin()
				.successHandler(this::loginSuccessHandler);

		http.
				addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
				.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER").and()
				.withUser("admin").password("password").roles("USER", "ADMIN");

		auth.userDetailsService(customUserDetailService).passwordEncoder(bCryptPasswordEncoder);
	}

	//Generate a JWT after successful login
	private void loginSuccessHandler(
			HttpServletRequest request,
			HttpServletResponse response,
			Authentication authentication) throws IOException {

		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

		String compactJws = Jwts.builder()
				.claim("user", authentication.getPrincipal())
				.setIssuedAt(new Date())
				.setExpiration(expiryDate)
				.signWith(SignatureAlgorithm.HS512, jwtSecret)
				.compact();

		response.setStatus(HttpStatus.OK.value());
		response.setHeader("accessToken", compactJws);
	}
}
