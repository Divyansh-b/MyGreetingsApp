package org.springboot.greetingapp.Services;

import org.springboot.greetingapp.Entities.MessageEntity;
import org.springboot.greetingapp.Model.Message;
import org.springboot.greetingapp.Repository.GreetingRepository;
import org.springframework.stereotype.Service;



@Service
public class GreetingServices {
    String greeting;
    GreetingRepository greetingRepository;
    public GreetingServices() {
        greeting = "Hello User";
    }
    public String getGreeting() {
        return greeting;
    }
    public void setGreeting(String greeting) {
        this.greeting = greeting;
    }
    public Message save(Message message){
        MessageEntity me = new MessageEntity(message.getMessage());

        greetingRepository.save(me);

        Message Info = new Message(me.getMessage());

        Info.setMessageID(me.getId());

        return Info;
    }
    public Message findbyID(Long ID){
        MessageEntity me = greetingRepository.findById(ID).orElseThrow(()->new RuntimeException("No Record Found"));
        Message Info = new Message(me.getMessage());
        Info.setMessageID(me.getId());
        return Info;
    }
}
