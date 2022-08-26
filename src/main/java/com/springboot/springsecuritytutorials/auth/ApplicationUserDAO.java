package com.springboot.springsecuritytutorials.auth;


import com.springboot.springsecuritytutorials.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ApplicationUserDAO {
    Optional<ApplicationUser> getUserByUsername(String username);
}
