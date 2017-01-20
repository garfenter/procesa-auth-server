package com.procesa.procesa.auth.server;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 *
 * @author Juan Luis Cano <garfenter at adstter.com>
 */
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private DataSource dataSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin().loginPage("/login").permitAll().and().authorizeRequests()
                .anyRequest().authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery("SELECT name username, password, 1 enabled FROM USER WHERE name = ?")
                .authoritiesByUsernameQuery("SELECT u.name username, p.name authority "
                        + "FROM USER u "
                        + "INNER JOIN USER_ROLE ur ON (ur.user = u.dbid) "
                        + "INNER JOIN ROLE_PERMISSION rp ON (ur.role = rp.role) "
                        + "INNER JOIN PERMISSION p ON (p.dbid = rp.permission) WHERE "
                        + "u.name = ?");

        auth.parentAuthenticationManager(authenticationManager);
    }
}
