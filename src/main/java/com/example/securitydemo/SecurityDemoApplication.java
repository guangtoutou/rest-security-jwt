package com.example.securitydemo;

import com.example.securitydemo.model.ApplicationUser;
import com.example.securitydemo.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class SecurityDemoApplication {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder bbCryptPasswordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(SecurityDemoApplication.class, args);
	}

	@PostMapping("/signup")
	public ResponseEntity<ApplicationUser> signup(@RequestBody ApplicationUser userForm){
		userForm.setPassword(bbCryptPasswordEncoder.encode(userForm.getPassword()));
		ApplicationUser user = userRepository.save(userForm);
		return ResponseEntity.ok(user);
	}
}