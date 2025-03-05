package org.springboot.greetingapp.Services;

import org.springboot.greetingapp.Entities.MessageEntity;
import org.springboot.greetingapp.Interfaces.IGreetingInterface;
import org.springboot.greetingapp.Model.Message;
import org.springboot.greetingapp.Repository.GreetingRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


@Service
public class  GreetingServices implements IGreetingInterface {

    String greeting;
    GreetingRepository greetingRepository;

    public GreetingServices() {
        greeting = "Hello User";
        this.greetingRepository = greetingRepository;

    }
    public String getGreeting() {
        return this.greeting;
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
    public Message findById(Long ID){
        MessageEntity me = greetingRepository.findById(ID).orElseThrow(()->new RuntimeException("No Record Found"));
        Message Info = new Message(me.getMessage());
        Info.setMessageID(me.getId());
        return Info;
    }
    public List<Message> listAllMessages(){
      List<Message> list  = greetingRepository.findAll().stream().map(me ->{
           Message Info = new Message(me.getMessage());
           Info.setMessageID(me.getId());
           return Info;
      }).collect(Collectors.toList());
      return list;
    }
    public Message updateById (Message message, Long ID){
        MessageEntity me = greetingRepository.findById(ID).orElseThrow(()->new RuntimeException("No Record Found"));
        me.setMessage(message.getMessage());
        greetingRepository.save(me);
        Message Info = new Message(me.getMessage());
        Info.setMessageID(me.getId());
        return Info;
    }

    public String deleteMessage(Long ID){
        MessageEntity me = greetingRepository.findById(ID).orElseThrow(()->new RuntimeException("No Record Found"));
        greetingRepository.delete(me);
        return "Deleted Successfully";
    }
}



