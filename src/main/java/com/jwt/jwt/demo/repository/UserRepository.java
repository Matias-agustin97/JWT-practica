package com.jwt.jwt.demo.repository;

import com.jwt.jwt.demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

//Remember, if you use long for id, use Long, for int, Integer



public interface UserRepository extends JpaRepository<User,Integer> {

    //We use optional because the query can return our object from the db, or return null if it doesnt exist
    ///Optional has a method to check if it exist


    Optional<User> findByEmail(String email);

}
