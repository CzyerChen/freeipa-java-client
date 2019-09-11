package freeipa.boot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Created by claire on 2019-09-09 - 16:03
 **/
@SpringBootApplication
public class IPABootApplication {

    public static void main (String[] args){
        SpringApplication.run(IPABootApplication.class,args);
    }
}
