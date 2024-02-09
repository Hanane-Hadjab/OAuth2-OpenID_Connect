package com.security.repository;

import com.security.model.DBUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DBUserRepository extends JpaRepository<DBUser, Integer> {
    public DBUser findByUsername(String username);
}
