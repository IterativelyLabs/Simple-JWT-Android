package com.iterativelylabs.simplejwt

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import java.util.Date

data class JWTPayload(
    val issuer: String?,
    val subject: String?,
    val expiresAt: Date?,
    val notBefore: Date?,
    val issuedAt: Date?,
    val id: String?,
    val audience: List<String>?,
    val claims: Map<String, JWTClaim>?) {

    fun claimOrNull(claimName: String) : JWTClaim? {
        return claims?.get(claimName)
    }

    fun claimValueAsString(claimName: String) : String? {
        return claimOrNull(claimName)?.valueAsString()
    }

    fun claimValueAsJsonObject(claimName: String) : JsonObject? {
        return claimOrNull(claimName)?.valueAsJsonObject()
    }
}

data class JWTClaim(val value: JsonElement) {
    fun valueAsJsonObject() : JsonObject? {
        return if (value.isJsonObject) { value.asJsonObject } else { null }
    }

    fun valueAsString() : String? {
        return if (value.isJsonPrimitive) { value.asString} else { null }
    }
}