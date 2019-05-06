package com.iterativelylabs.simplejwt

import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import java.lang.reflect.Type
import com.google.gson.JsonObject
import java.util.*


class JWTPayloadDeserializer : JsonDeserializer<JWTPayload> {

    private val RegisteredClaimNames = listOf("iss", "sub", "exp", "nbf", "iat", "jti", "aud")

    override fun deserialize(
        jsonElement: JsonElement?,
        type: Type?,
        context: JsonDeserializationContext?
    ): JWTPayload? {
        var payload: JWTPayload? = null

        jsonElement?.asJsonObject?.run {

            val issuer = getStringOrNull("iss")
            val subject = getStringOrNull("sub")
            val expiresAt = getDateOrNull("exp")
            val notBefore = getDateOrNull("nbf")
            val issuedAt = getDateOrNull("iat")
            val tokenId = getStringOrNull("jti")
            val claims = mutableMapOf<String, JWTClaim>()

            entrySet().forEach { entry ->
                if (!isRegisteredClaimName(entry.key)) {
                    claims.put(entry.key, JWTClaim(entry.value))
                }
            }

            payload = JWTPayload(issuer, subject, expiresAt, notBefore, issuedAt, tokenId, listOf(), claims.toMap())
        }

        return payload
    }

    private fun isRegisteredClaimName(claimName: String) = claimName in RegisteredClaimNames

    private fun JsonObject.getOrNull(name: String): JsonElement? {
        return if (has(name)) {
            get(name)
        } else {
            null
        }
    }

    private fun JsonObject.getStringOrNull(claimName: String): String? {
        return getOrNull(claimName)?.asString
    }

    private fun JsonObject.getDateOrNull(claimName: String): Date? {
        val longValue = getOrNull(claimName)?.asLong

        return if (longValue != null) {
            Date(longValue * 1000)
        } else {
            null
        }
    }
}
