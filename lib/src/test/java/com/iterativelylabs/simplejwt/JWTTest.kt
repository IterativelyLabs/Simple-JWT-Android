package com.iterativelylabs.simplejwt

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*

@RunWith(AndroidJUnit4::class)
class JWTTest {

    @Test
    fun `test HS256 JWT token with no private claims`() {
        val tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3ZjcyN2ZjNy05OWE2LTRiOTMtYTljZi1mYTg0MTc2Mjk2ZmEiLCJpYXQiOjE1NTc0Nzk4ODB9.qdwAtmsTuo87rOOIX73Ea07JdvH8y6B6_RsOjrN0R9I"

        val jwt = JWT(tokenString)

        assertEquals(2, jwt.header.size)
        assertEquals("HS256", jwt.header["alg"])
        assertEquals("JWT", jwt.header["typ"])

        assertEquals("7f727fc7-99a6-4b93-a9cf-fa84176296fa", jwt.payload?.subject)
        assertEquals(1557479880L, jwt.payload?.issuedAt?.toMilliseconds())

        assertEquals(0, jwt.payload?.claims?.size)
    }

    @Test
    fun `test HS256 JWT token with nested private claims object`() {
        val tokenString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2F1dGgudGVzdHNpbXBsZWp3dC5jby51ay8iLCJzdWIiOiI1MmU1NTA0NC1kNGJkLTQ5ZWYtYWYwMS01MmU4ZTMyOWIxNDgiLCJkYXRhIjp7ImFzc29jaWF0ZWRJZCI6IjUyODEzMGMwLTYxMDktNDkxNC1hMDRlLTgzZDA2YjQ4MjVhNCJ9LCJqdGkiOiJmMThhMjg3MS02OTk4LTQ5NmYtYTMxNC1hYmFjN2IzN2JjYTQiLCJpYXQiOjE1NTY4OTkyMDAsImV4cCI6MTU1NjkwMDEwMH0.b8Peq6VMlHN2R4ak7GFKjDDgw0J7JSl_w8geNHX1XQI"

        val jwt = JWT(tokenString)

        assertEquals(2, jwt.header.size)
        assertEquals("HS256", jwt.header["alg"])
        assertEquals("JWT", jwt.header["typ"])

        assertEquals("https://auth.testsimplejwt.co.uk/", jwt.payload?.issuer)
        assertEquals("52e55044-d4bd-49ef-af01-52e8e329b148", jwt.payload?.subject)
        assertEquals("f18a2871-6998-496f-a314-abac7b37bca4", jwt.payload?.id)
        assertEquals(1556899200L, jwt.payload?.issuedAt?.toMilliseconds())
        assertEquals(1556900100L, jwt.payload?.expiresAt?.toMilliseconds())

        assertEquals(1, jwt.payload?.claims?.size)
        assertNotNull(jwt.payload?.claimValueAsJsonObject("data"))

        val dataClaim = jwt.payload?.claimOrNull("data")?.valueAsJsonObject()

        assertEquals("528130c0-6109-4914-a04e-83d06b4825a4", dataClaim?.get("associatedId")?.asString)
    }

    @Test
    fun `test HS256 JWT token with primitive private claim`() {
        val tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        val jwt = JWT(tokenString)

        assertEquals(2, jwt.header.size)
        assertEquals("HS256", jwt.header["alg"])
        assertEquals("JWT", jwt.header["typ"])

        assertEquals("1234567890", jwt.payload?.subject)
        assertEquals(1516239022L, jwt.payload?.issuedAt?.toMilliseconds())

        assertEquals(1, jwt.payload?.claims?.size)
        assertEquals(true, jwt.payload?.claims?.containsKey("name"))
        assertEquals("John Doe", jwt.payload?.claimValueAsString("name"))
    }
}

fun Date.toMilliseconds() = time.div(1000)
