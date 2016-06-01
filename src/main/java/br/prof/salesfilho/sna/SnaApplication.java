package br.prof.salesfilho.sna;

import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SnaApplication {
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(SnaApplication.class);
        app.setBannerMode(Banner.Mode.OFF);
        app.run(args);
    }
}
