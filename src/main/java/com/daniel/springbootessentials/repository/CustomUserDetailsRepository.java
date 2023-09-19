package com.daniel.springbootessentials.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.daniel.springbootessentials.domain.CustomUserDetails;

public interface CustomUserDetailsRepository extends JpaRepository<CustomUserDetails, Long> {

    CustomUserDetails findByUsername(String username);
}
