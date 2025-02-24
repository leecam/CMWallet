package com.credman.cmwallet.openid4vp

import android.util.Base64
import com.credman.cmwallet.cbor.cborEncode
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.jweSerialization
import org.json.JSONObject
import java.security.MessageDigest

data class TransactionData(
    val encodedData: String,
    val type: String,
    val credentialIds: List<String>,
    val data: JSONObject
)

class OpenId4VP(val request: String, val clientId: String) {
    val requestJson: JSONObject = JSONObject(request)

    val nonce: String

    val dcqlQuery: JSONObject
    val transactionData: List<TransactionData>
    val issuanceOffer: JSONObject?
    val clientMedtadata: JSONObject?
    val responseMode: String?

    init {
        // Parse required params
        require(requestJson.has("nonce")) { "Authorization Request must contain a nonce" }
        require(requestJson.has("dcql_query")) { "Authorization Request must contain a dcql_query" }

        nonce = requestJson.getString("nonce")
        dcqlQuery = requestJson.getJSONObject("dcql_query")
        issuanceOffer = requestJson.optJSONObject("offer")
        clientMedtadata = requestJson.optJSONObject("client_metadata")
        responseMode = requestJson.optString("response_mode")

        val transactionDataJson = requestJson.optJSONArray("transaction_data")
        if (transactionDataJson != null) {
            val tempList = mutableListOf<TransactionData>()
            for (i in 0 until transactionDataJson.length()) {
                val transactionDataItemEncoded = transactionDataJson.getString(i)
                val transactionDataItemJson =
                    Base64.decode(transactionDataItemEncoded, Base64.URL_SAFE)
                        .toString(Charsets.UTF_8)
                val transactionDataItem = JSONObject(transactionDataItemJson)
                val credentialIds = mutableListOf<String>()
                val credentialIdsJson = transactionDataItem.getJSONArray("credential_ids")
                for (j in 0 until credentialIdsJson.length()) {
                    credentialIds.add(credentialIdsJson.getString(j))
                }

                tempList.add(
                    TransactionData(
                        transactionDataItemEncoded,
                        transactionDataItem.getString("type"),
                        credentialIds,
                        transactionDataItem
                    )
                )
            }
            transactionData = tempList
        } else {
            transactionData = emptyList()
        }

    }

    data class TransactionDataResult(
        val deviceSignedTransactionData: Map<String, List<ByteArray>>,
        val authenticationTitleAndSubtitle: Pair<CharSequence, CharSequence?>?,
    )

    fun generateDeviceSignedTransactionData(dcqlId: String): TransactionDataResult {
        if (transactionData.isEmpty()) {
            return TransactionDataResult(emptyMap(), null)
        }
        val transactionDataHashes = mutableListOf<ByteArray>()
        var authenticationTitleAndSubtitle: Pair<CharSequence, CharSequence?>? = null
        for (transactionDataItem in transactionData) {
            if (dcqlId in transactionDataItem.credentialIds) {
                val md = MessageDigest.getInstance("SHA-256")
                transactionDataHashes.add(md.digest(transactionDataItem.encodedData.encodeToByteArray()))
                val decoded = JSONObject(
                    String(
                        Base64.decode(
                            transactionDataItem.encodedData,
                            Base64.URL_SAFE
                        )
                    )
                )
                val merchantName = decoded.optString(MERCHANT_NAME)
                val amount = decoded.optString(AMOUNT)
                if (!merchantName.isNullOrBlank() && !amount.isNullOrBlank()) {
                    authenticationTitleAndSubtitle = Pair(
                        "Confirm transaction",
                        "Authorize payment of amount $amount to $merchantName."
                    )
                }
            }
        }
        return TransactionDataResult(
            mapOf(
                Pair(
                    "transaction_data_hashes",
                    transactionDataHashes.toList()
                )
            ),
            authenticationTitleAndSubtitle,
        )
    }

    fun matchCredentials(credentialStore: JSONObject): Map<String, List<MatchedCredential>> {
        return DCQLQuery(dcqlQuery, credentialStore)
    }

    fun performQueryOnCredential(selectedCredential: CredentialItem): OpenId4VPMatchedCredential {
        return performQueryOnCredential(dcqlQuery, selectedCredential)
    }

    fun getHandover(origin: String): List<Any> {
        /**
         * Shape of `OpenID4VPDCAPIHandover[0]`
         *
         * See https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-B.3.4.1
         */
        val oid4vpHandoverIdentifier = "OpenID4VPDCAPIHandover";

        /**
         * Shape of `OpenID4VPDCAPIHandoverInfo`
         *
         * See https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-B.3.4.1
         */
        val handoverData = listOf(
            origin,
            clientId,
            nonce
        )

        val md = MessageDigest.getInstance("SHA-256")
        return listOf(
            oid4vpHandoverIdentifier,
            md.digest(cborEncode(handoverData))
        )
    }

    fun generateResponse(vpToken: JSONObject): String {
        val responseJson = JSONObject().put("vp_token", vpToken).toString()
        val response = if (responseMode == "dc_api.jwt") {
            // Encrypt response if applicable
            val encryptionAgl = clientMedtadata?.opt("authorization_encrypted_response_alg")
            val encryptionEnc = clientMedtadata?.opt("authorization_encrypted_response_enc")
            val signAgl = clientMedtadata?.opt("authorization_signed_response_alg")
            val jwks = clientMedtadata?.opt("jwks")
            if (encryptionAgl != null && encryptionEnc != null && signAgl == null) {
                require(encryptionAgl == "ECDH-ES" && encryptionEnc == "A128GCM") { "Unsupported encryption algorithm" }
                val jwks = (jwks!! as JSONObject).getJSONArray("keys")
                var encryptionJwk = jwks[0] as JSONObject
                for (i in 0..<jwks.length()) {
                    val jwk = jwks[i] as JSONObject
                    if (jwk.has("use")
                        && jwk["use"] == "enc"
                        && encryptionJwk["kty"] == "EC"
                        && encryptionJwk["crv"] == "P-256"
                    ) {
                        encryptionJwk = jwk
                    }
                }
                jweSerialization(encryptionJwk, responseJson)
            } else {
                throw UnsupportedOperationException("Response should be signed and / or encrypted but it's not supported yet")
            }
        } else {
            responseJson
        }
        return response
    }

    companion object {
        const val MERCHANT_NAME = "merchant_name"
        const val AMOUNT = "amount"
    }
}