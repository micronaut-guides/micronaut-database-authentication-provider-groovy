package example.micronaut.services

import example.micronaut.domain.User
import io.micronaut.context.annotation.Replaces
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.providers.AuthoritiesFetcher
import io.micronaut.security.authentication.providers.DelegatingAuthenticationProvider
import io.micronaut.security.authentication.providers.PasswordEncoder
import io.micronaut.security.authentication.providers.UserFetcher
import io.micronaut.security.authentication.providers.UserState
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

@Singleton
@Replaces(DelegatingAuthenticationProvider)
class CustomDelegatingAuthenticationProvider extends DelegatingAuthenticationProvider {

    CustomDelegatingAuthenticationProvider(UserFetcher userFetcher, PasswordEncoder passwordEncoder, AuthoritiesFetcher authoritiesFetcher) {
        super(userFetcher, passwordEncoder, authoritiesFetcher)
    }

    @Override
    protected Publisher<AuthenticationResponse> createSuccessfulAuthenticationResponse(AuthenticationRequest authenticationRequest, UserState userState) {
        if (userState instanceof User) {
            User user = (User) userState
            return Flowable
                    .fromPublisher(authoritiesFetcher.findAuthoritiesByUsername(user.getUsername()))
                    .map { authorities -> new EmailUserDetails(user.email, user.getUsername(), authorities) }
        }
        super.createSuccessfulAuthenticationResponse(authenticationRequest, userState)
    }
}
