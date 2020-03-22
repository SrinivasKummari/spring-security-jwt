package com.codelunatic.springsecurityjwt.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.codelunatic.springsecurityjwt.filters.JWTRequestFilter;
import com.codelunatic.springsecurityjwt.service.MyUserDetailsService;
@Configuration
@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter{

	
	@Autowired
	private MyUserDetailsService userDetailsService;
	
	@Autowired
	private JWTRequestFilter jwtRequestFiler;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		System.out.println("In SecurityConfigurer AuthenticationManagerBuilder");
		auth.userDetailsService(userDetailsService);
	}

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		System.out.println("In SecurityConfigurer HttpSecurity");
		http.csrf().disable()
			.authorizeRequests().antMatchers("/authenticate").permitAll()//if uri matches it disable authentication
			.anyRequest().authenticated()//rest all need to authenticate
			.and().sessionManagement()//Adding session management criteria
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS);//making spring boot app stateless. JWT is to make app stateless
		http.addFilterBefore(jwtRequestFiler, UsernamePasswordAuthenticationFilter.class);//Before adding filer, first perform jwt request filter.
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}
