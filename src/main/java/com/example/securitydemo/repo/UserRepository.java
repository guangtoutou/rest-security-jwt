package com.example.securitydemo.repo;

import com.example.securitydemo.model.ApplicationUser;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<ApplicationUser, Long> {

	public ApplicationUser findApplicationUserByUsername(String username);

}
