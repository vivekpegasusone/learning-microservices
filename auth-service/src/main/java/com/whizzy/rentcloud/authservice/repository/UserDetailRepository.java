package com.whizzy.rentcloud.authservice.repository;

import com.whizzy.rentcloud.authservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserDetailRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String userName);
}
