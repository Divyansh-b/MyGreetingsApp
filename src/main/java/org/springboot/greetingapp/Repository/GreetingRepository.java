package org.springboot.greetingapp.Repository;

import org.springboot.greetingapp.Entities.MessageEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.yaml.snakeyaml.events.Event;


    @Repository
    public interface GreetingRepository extends JpaRepository<MessageEntity, Long> {


    }

