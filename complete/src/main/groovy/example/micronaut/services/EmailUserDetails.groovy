package example.micronaut.services

import groovy.transform.CompileStatic
import io.micronaut.security.authentication.UserDetails

@CompileStatic
class EmailUserDetails extends UserDetails {
    String email

    EmailUserDetails(String email, String username, Collection<String> roles) {
        super(username, roles)
        this.email = email
    }


}
