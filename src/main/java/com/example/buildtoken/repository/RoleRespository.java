package com.example.buildtoken.repository;

import com.example.buildtoken.model.ERole;
import com.example.buildtoken.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRespository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
