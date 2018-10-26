package io.vipin.dtc;

import java.security.Principal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
//Enables Spring Boot’s auto-configuration mechanism, package scan, and registering extra beans in the
//context or import additional configuration classes
@EnableOAuth2Sso //Enables OAuth2 Single Sign On, will automatically use application.yml properties for security
@RestController //Enabling REST functionality. With this, we can now expose our own endpoints
public class W3authenticateApplication extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(W3authenticateApplication.class, args);
	}
	
	@Override
    protected void configure(HttpSecurity http) throws Exception {

        //Configuring Spring security access. For /login, /user, and /userinfo, we need authentication.
        //Logout is enabled.
        //Adding csrf token support to this configurer.
        http.authorizeRequests()
                .antMatchers("/login**", "/user","/userInfo").permitAll()
                .and().logout().logoutSuccessUrl("/").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

    }
	Object p;
	
	@RequestMapping("/user")
    public Principal user(Principal principal) {
        //Principal holds the logged in user information.
        // Spring automatically populates this principal object after login.
		System.out.println(principal.toString());
        return principal;
    }

    @RequestMapping("/userInfo")
    public String userInfo(Principal principal){
        final OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
        final Authentication authentication = oAuth2Authentication.getUserAuthentication();
        //Manually getting the details from the authentication, and returning them as String.
        p=authentication.getDetails();
        return authentication.getDetails().toString();
    }
    
    @RequestMapping("/hello")
    public Object hello() {
//    	Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//    	return auth.getDetails();
    	System.out.println(p);
    	return p;
    	}
	
}
