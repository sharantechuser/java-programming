package com.javatechuser24.oauthauthserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
public class OauthAuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthAuthServerApplication.class, args);
	}

}
