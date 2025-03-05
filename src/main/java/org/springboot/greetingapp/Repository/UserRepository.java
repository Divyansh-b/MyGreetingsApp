package org.springboot.greetingapp.Repository;

import org.springboot.greetingapp.Entities.Auth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository <Auth,Long>{



}
