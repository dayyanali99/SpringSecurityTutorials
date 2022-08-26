package com.springboot.springsecuritytutorials;

import com.springboot.springsecuritytutorials.auth.ApplicationUser;
import com.springboot.springsecuritytutorials.auth.ApplicationUserDAO;
import com.springboot.springsecuritytutorials.entities.User;
import com.springboot.springsecuritytutorials.security.ApplicationUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@SpringBootApplication
public class SpringSecurityTutorialsApplication implements CommandLineRunner {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private ApplicationUserDAO applicationUserDAO;

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityTutorialsApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
//		User user1 = new User("linda", passwordEncoder.encode("password123"), ApplicationUserRole.ADMIN.getGrantedAuthorities());
//		User user2 = new User("tom", passwordEncoder.encode("password123"), ApplicationUserRole.ADMIN_TRAINEE.getGrantedAuthorities());
//
//		applicationUserDAO.save(user1);
//		applicationUserDAO.save(user2);

//		Optional<User> lindaOptional = this.applicationUserDAO.getUserByUsername("linda");
//		System.out.println(lindaOptional.get());
	}
}
