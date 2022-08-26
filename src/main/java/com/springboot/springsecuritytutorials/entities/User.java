package com.springboot.springsecuritytutorials.entities;

import lombok.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.*;
import java.util.Set;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class User {
    @Id
    public String username;
    public String password;
    @ElementCollection(fetch = FetchType.EAGER)
    public Set<SimpleGrantedAuthority> authorities;
}
