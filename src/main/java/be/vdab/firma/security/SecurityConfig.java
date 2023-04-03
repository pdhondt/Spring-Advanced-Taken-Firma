package be.vdab.firma.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {
    private static final String GEBRUIKER = "gebruiker";
    private final DataSource dataSource;

    public SecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    JdbcUserDetailsManager maakPrincipals() {
        var manager = new JdbcUserDetailsManager(dataSource);
        manager.setUsersByUsernameQuery(
                """
                        select emailAdres as username, paswoord as password, true as enabled
                        from werknemers
                        where emailAdres = ?
                        """
        );
        manager.setAuthoritiesByUsernameQuery("select ?, 'gebruiker'");
        return manager;
    }
    @Bean
    SecurityFilterChain geefRechten(HttpSecurity http) throws Exception {
        http.formLogin();
        http.authorizeHttpRequests(requests -> requests
                .requestMatchers("/images/**", "/css/**", "/js/**", "/",
                        "/index.html").permitAll()
                .requestMatchers("/geluksgetal.html")
                .hasAuthority(GEBRUIKER));
        return http.build();
    }

}
