package example.micronaut.services

import com.nimbusds.jwt.JWTClaimsSet
import groovy.transform.InheritConstructors
import io.micronaut.context.annotation.Replaces
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.token.config.TokenConfiguration
import io.micronaut.security.token.jwt.generator.claims.ClaimsAudienceProvider
import io.micronaut.security.token.jwt.generator.claims.JWTClaimsSetGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtIdGenerator

import javax.annotation.Nullable
import javax.inject.Singleton

@InheritConstructors
@Singleton
@Replaces(JWTClaimsSetGenerator)
class CustomJWTClaimsSetGenerator extends JWTClaimsSetGenerator {

    CustomJWTClaimsSetGenerator(TokenConfiguration tokenConfiguration, @Nullable JwtIdGenerator jwtIdGenerator, @Nullable ClaimsAudienceProvider claimsAudienceProvider) {
        super(tokenConfiguration, jwtIdGenerator, claimsAudienceProvider)
    }

    protected void populateWithUserDetails(JWTClaimsSet.Builder builder, UserDetails userDetails) {
        super.populateWithUserDetails(builder, userDetails)
        if (userDetails instanceof EmailUserDetails) {
            builder.claim('email', ((EmailUserDetails) userDetails).email)
        }
    }


}
