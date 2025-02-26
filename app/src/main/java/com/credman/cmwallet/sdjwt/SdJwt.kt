package com.credman.cmwallet.sdjwt

import android.util.Log
import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.toBase64UrlNoPadding
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.jwt.JwkSetConverter
import com.google.crypto.tink.jwt.JwtPublicKeyVerify
import com.google.crypto.tink.jwt.JwtSignatureConfig
import com.google.crypto.tink.jwt.JwtValidator
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

class SdJwt(
    credential: String
) {
    val issuerJwt: String
    val disclosures: List<String>
    val kb: String?
    init {
        val composition = credential.split('~')
        issuerJwt = composition[0]
        disclosures =
            if (composition.size <= 1) emptyList()
            else composition.subList(1, composition.size - 1)
        kb = if (composition.last() == "~") null else composition.last()
    }

    val verifiedResult: VerificationResult by lazy {
        verify(issuerJwt, disclosures)
    }
}

class VerificationResult(
    val processedJwt: JSONObject,
    val digestDisclosureMap: Map<String, JSONArray>
)

fun verify(issuerJwt: String, disclosures: List<String>): VerificationResult {
    val testIssuerJwk = JSONObject().apply {
        put("alg", "ES256") // TODO: should get from jwt header?
        put("kty", "EC")
        put("crv", "P-256")
        put("x", "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ")
        put("y", "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8")
    }
    JwtSignatureConfig.register()
    val publicKeysetHandle = JwkSetConverter.toPublicKeysetHandle(
        JSONObject().put("keys", JSONArray().apply {
            put(testIssuerJwk)
        }).toString())
    val verifier =
        publicKeysetHandle.getPrimitive(
            RegistryConfiguration.get(),
            JwtPublicKeyVerify::class.java
        )
    val validator = JwtValidator.newBuilder()
        .expectTypeHeader("dc+sd-jwt")
        .expectIssuer("https://example.com/issuer")
        .ignoreAudiences()
        .build()
    val verifiedJwt = verifier.verifyAndDecode(issuerJwt, validator)

    if (verifiedJwt.customClaimNames().contains("_sd_alg")) {
        assert(verifiedJwt.getStringClaim("_sd_alg") == "sha-256") {"Only support sha-256"}
    }

    val digestDisclosureMap = mutableMapOf<String, JSONArray>()
    for (disclosure in disclosures) {
        val decoded = disclosure.decodeBase64UrlNoPadding().decodeToString()
        val disclosureJson = JSONArray(decoded)
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(disclosure.encodeToByteArray()).toBase64UrlNoPadding()
        digestDisclosureMap[digest] = disclosureJson
    }
    val finalDigestDisclosureMap = digestDisclosureMap.toMap()
    val rawPayload = issuerJwt.split('.')[1] // Assume compact
    val payload = JSONObject(rawPayload.decodeBase64UrlNoPadding().decodeToString())
    val processedJwt = verifyInternal(payload, digestDisclosureMap, mutableSetOf()) as JSONObject
    assert(digestDisclosureMap.isEmpty()) { "All disclosures must be referenced in the issuer jwt" }
    processedJwt.remove("_sd_alg")
    return VerificationResult(processedJwt, finalDigestDisclosureMap)
}

private fun verifyInternal(input: Any, digestDisclosureMap: MutableMap<String, JSONArray>, seenDigest: MutableSet<String>): Any {
    when (input) {
        is JSONObject -> {
            val processed = JSONObject()
            for (k in input.keys()) {
                val v = input.get(k)
                if (k == "_sd") {
                    val sdDigests = v as JSONArray
                    for (i in 0..<sdDigests.length()) {
                        val digest = sdDigests[i] as String
                        assert(!seenDigest.contains(digest)) { "Digest seen more than once: $digest" }
                        seenDigest.add(digest)
                        val disclosure = digestDisclosureMap.remove(digest)
                        if (disclosure != null) {
                            assert(disclosure.length() == 3) { "Validation failed: Invalid disclosure length. expected: 3" }
                            val claimName = disclosure[1] as String
                            assert(claimName != "_sd") { "Validation failed: claim name cannot be _sd"}
                            assert(claimName != "...") { "Validation failed: claim name cannot be ..."}
                            assert(!input.has(claimName)) { "Validation failed: claim name $claimName already exists"}
                            val claimValue = disclosure[2]
                            processed.put(claimName, verifyInternal(claimValue, digestDisclosureMap, seenDigest))
                        }
                    }
                } else {
                    processed.put(k, verifyInternal(v, digestDisclosureMap, seenDigest))
                }
            }
            return processed
        }
        is JSONArray -> {
            val processed = JSONArray()
            for (i in 0..<input.length()) {
                val arrElement = input[i]
                if (arrElement is JSONObject && arrElement.length() == 1 && arrElement.has("...")) {
                    val digest = arrElement["..."] as String
                    assert(!seenDigest.contains(digest)) { "Digest seen more than once: $digest" }
                    seenDigest.add(digest)
                    val disclosure = digestDisclosureMap.remove(digest)
                    if (disclosure != null) {
                        assert(disclosure.length() == 2) { "Validatiodn failed: Invalid disclosure length. expected: 2" }
                        val claimValue = disclosure[1]
                        processed.put(verifyInternal(claimValue, digestDisclosureMap, seenDigest))
                    }
                } else {
                    processed.put(verifyInternal(arrElement, digestDisclosureMap, seenDigest))
                }
            }
            return processed
        }
        else -> return input
    }
}