package com.iterativelylabs.simplejwt

import android.util.Base64
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import java.lang.reflect.Type
import java.util.*

class JWT(private val token: String) {

    internal val stringMapType:Type = object : TypeToken<Map<String, String>>(){ }.type
    internal val gson: Gson

    var header = mapOf<String,String>()
        private set

    var payload:JWTPayload? = null
        private set

    var signature : String = ""
        private set


    companion object {
        // no-op but here so class level extensions are possible
    }

    init {
        gson = GsonBuilder().registerTypeAdapter(JWTPayload::class.java, JWTPayloadDeserializer()).create()
        decodeToken()
    }

    private fun decodeToken() {
        if (token.isEmpty() || token.count { it == '.' }  != 2) throw IllegalArgumentException("Token is empty or incorrectly formatted")

        val parts = arrayOf("","","")
        token.split(".").forEachIndexed { index, part ->
            parts[index] = part
        }

        if (parts[2].isEmpty()) throw IllegalArgumentException("Signature is missing from Token")

        header = decodeToType(parts[0], stringMapType) ?: mapOf()
        payload = decodeToType(parts[1], JWTPayload::class.java) as? JWTPayload
        signature = parts[2]
    }

    private fun <T> decodeToType(string: String, typeOfT: Type): T? {
        val decodedJson = String(Base64.decode(string, Base64.URL_SAFE))
        return try { gson.fromJson(decodedJson, typeOfT) } catch (e : EnumConstantNotPresentException) { null }
    }
}