package com.credman.cmwallet.getcred

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreateCustomCredentialRequest
import androidx.credentials.CustomCredential
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.registry.provider.selectedEntryId
import androidx.fragment.app.FragmentActivity
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.CmWalletApplication.Companion.computeClientId
import com.credman.cmwallet.createcred.CreateCredentialActivity
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.CredentialKeySoftware
import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.getcred.GetCredentialActivity.DigitalCredentialResult
import com.credman.cmwallet.intToBigEndianByteArray
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.mdoc.createSessionTranscript
import com.credman.cmwallet.mdoc.filterIssuerSigned
import com.credman.cmwallet.mdoc.generateDeviceResponse
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationMDoc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationSdJwtVc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationUnknownFormat
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedCredential
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedMDocClaims
import com.credman.cmwallet.toBase64UrlNoPadding
import com.credman.cmwallet.toJWK
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.jose4j.jwe.kdf.ConcatKeyDerivationFunction
import org.json.JSONObject
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


fun createOpenID4VPResponse(
    openId4VPRequest: OpenId4VP,
    origin: String,
    selectedCredential: CredentialItem,
    matchedCredential: OpenId4VPMatchedCredential
): DigitalCredentialResult {
    var authenticationTitle: CharSequence = "Verify your identity"
    var authenticationSubtitle: CharSequence? = null
    // Create the response
    val vpToken = JSONObject()
    when (selectedCredential.config) {
        is CredentialConfigurationSdJwtVc -> {

        }
        is CredentialConfigurationMDoc -> {
            val matchedClaims =
                matchedCredential.matchedClaims as OpenId4VPMatchedMDocClaims
            val filteredIssuerSigned = filterIssuerSigned(
                selectedCredential.credentials.first().credential.decodeBase64UrlNoPadding(),
                matchedClaims.claims
            )
            val deviceNamespaces = if (openId4VPRequest.transactionData.isEmpty()) {
                emptyMap<String, Any>()
            } else {
                val deviceSignedTransactionData =
                    openId4VPRequest.generateDeviceSignedTransactionData(
                        matchedCredential.dcqlId
                    )
                if (deviceSignedTransactionData.authenticationTitleAndSubtitle != null) {
                    authenticationTitle =
                        deviceSignedTransactionData.authenticationTitleAndSubtitle.first
                    authenticationSubtitle =
                        deviceSignedTransactionData.authenticationTitleAndSubtitle.second
                }
                mapOf(
                    Pair(
                        "net.openid.open4vc",
                        deviceSignedTransactionData.deviceSignedTransactionData
                    )
                )
            }
            val devicePrivateKey =
                loadECPrivateKey((selectedCredential.credentials.first().key as CredentialKeySoftware).privateKey.decodeBase64UrlNoPadding())
            val deviceResponse = generateDeviceResponse(
                doctype = selectedCredential.config.doctype,
                issuerSigned = filteredIssuerSigned,
                devicePrivateKey = devicePrivateKey,
                sessionTranscript = createSessionTranscript(
                    openId4VPRequest.getHandover(
                        origin
                    )
                ),
                deviceNamespaces = deviceNamespaces

            )
            // Encrypt response, if applicable
            val encodedDeviceResponse = deviceResponse.toBase64UrlNoPadding()
            vpToken.put(matchedCredential.dcqlId, encodedDeviceResponse)
        }

        is CredentialConfigurationUnknownFormat -> TODO()
    }

    // Create the openid4vp result
    val responseJson = JSONObject().put("vp_token", vpToken).toString()
    val response = if (openId4VPRequest.responseMode == "dc_api.jwt") {
        // Encrypt response if applicable
        val encryptionAgl = openId4VPRequest.clientMedtadata?.opt("authorization_encrypted_response_alg")
        val encryptionEnc = openId4VPRequest.clientMedtadata?.opt("authorization_encrypted_response_enc")
        val signAgl = openId4VPRequest.clientMedtadata?.opt("authorization_signed_response_alg")
        val jwks = openId4VPRequest.clientMedtadata?.opt("jwks")
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
            val kid = encryptionJwk.optString("kid")
            val x = encryptionJwk.getString("x")
            val y = encryptionJwk.getString("y")
            val kf = KeyFactory.getInstance("EC")
            val parameters = AlgorithmParameters.getInstance("EC")
            parameters.init(ECGenParameterSpec("secp256r1"))
            val publicKey = kf.generatePublic(
                ECPublicKeySpec(
                    ECPoint(
                        BigInteger(1, x.decodeBase64UrlNoPadding()),
                        BigInteger(1, y.decodeBase64UrlNoPadding())
                    ),
                    parameters.getParameterSpec(ECParameterSpec::class.java)
                )
            )
            val kpg =  KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val kp = kpg.genKeyPair()
            val partyUInfo = ByteArray(0)
            val partyVInfo = ByteArray(0)
            val header = JSONObject()
            header.put("apu", partyUInfo.toBase64UrlNoPadding())
            header.put("apv", partyVInfo.toBase64UrlNoPadding())
            header.put("alg", "ECDH-ES")
            header.put("enc", "A128GCM")
            header.put("epk", JSONObject(kp.public.toJWK().toString()))
            val headerEncoded = header.toString().toByteArray().toBase64UrlNoPadding()

            val keyAgreement = KeyAgreement.getInstance("ECDH")
            keyAgreement.init(kp.private)
            keyAgreement.doPhase(publicKey, true)
            val sharedSecret = keyAgreement.generateSecret()
            val concatKdf = ConcatKeyDerivationFunction("SHA-256")

            val algOctets = (encryptionEnc as String).toByteArray()
            val keydatalen = 128

            val derivedKey = concatKdf.kdf(
                sharedSecret,
                keydatalen,
                intToBigEndianByteArray(algOctets.size) + algOctets,
                intToBigEndianByteArray(partyUInfo.size) + partyUInfo,
                intToBigEndianByteArray(partyVInfo.size) + partyVInfo,
                intToBigEndianByteArray(keydatalen),
                ByteArray(0)
            )
            val sks = SecretKeySpec(derivedKey, "AES")
            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)
            val ivEncoded = iv.toBase64UrlNoPadding()
            aesCipher.init(Cipher.ENCRYPT_MODE, sks, GCMParameterSpec(128, iv))
            aesCipher.updateAAD(headerEncoded.toByteArray())
            val encrypted = aesCipher.doFinal(vpToken.toString().toByteArray())
            val ct = encrypted.slice(0 until (encrypted.size - 16)).toByteArray()
            val ctEncoded = ct.toBase64UrlNoPadding()
            val tag = encrypted.slice((encrypted.size - 16) until encrypted.size).toByteArray()
            val tagEncoded = tag.toBase64UrlNoPadding()
            "${headerEncoded}..${ivEncoded}.${ctEncoded}.${tagEncoded}"
        } else {
            throw UnsupportedOperationException("Response should be signed and / or encrypted but it's not supported yet")
        }
    } else {
        responseJson
    }
    Log.d(TAG, "Returning $response")
    return DigitalCredentialResult(
        responseJson = response,
        authenticationTitle = authenticationTitle,
        authenticationSubtitle = authenticationSubtitle,
    )
}

class GetCredentialActivity : FragmentActivity() {
    private var request: ProviderGetCredentialRequest? = null

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        Log.d(TAG, "Got activity result from issuance")
        val newEntryId = data?.getStringExtra("newEntryId")!!
        handleRequest(
            JSONObject().put("provider_idx", 0).put("id", newEntryId).toString(),
            request!!
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        this.request = request
        if (request != null) {
            Log.i(TAG, "selectedEntryId ${request.selectedEntryId}")
            handleRequest(request.selectedEntryId, request)
        }
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    fun handleRequest(entryId: String?, request: ProviderGetCredentialRequest) {
        var origin = request.callingAppInfo.getOrigin(
            CmWalletApplication.credentialRepo.privAppsJson
        ) ?: ""
        Log.i("GetCredentialActivity", "origin $origin")
        if (origin.endsWith(":443")) {
            origin = origin.substringBefore(":443")
            Log.i("GetCredentialActivity", "new origin $origin")
        }

        request.credentialOptions.forEach {
            if (it is GetDigitalCredentialOption) {
                val resultData = Intent()
                Log.i(TAG, "Request ${it.requestJson}")

                try {
                    val digitalCredentialRequestOptions =
                        Json.decodeFromString<DigitalCredentialRequestOptions>(it.requestJson)
                    if (entryId == "ISSUANCE") {
                        val openId4VPRequest = OpenId4VP(
                            digitalCredentialRequestOptions.providers[0].request,
                            computeClientId(request.callingAppInfo)
                        )
                        startActivityForResult(
                            Intent(this, CreateCredentialActivity::class.java).apply {
                                val callingAppInfo = request.callingAppInfo
                                val providerRequest =
                                    ProviderCreateCredentialRequest(
                                        CreateCustomCredentialRequest(
                                            type = it.type,
                                            credentialData = Bundle().apply {
                                                putString(
                                                    "androidx.credentials.BUNDLE_KEY_REQUEST_JSON",
                                                    JSONObject()
                                                        .put("protocol", "openid4vci")
                                                        .putOpt("data", openId4VPRequest.issuanceOffer)
                                                        .toString()
                                                )
                                            },
                                            candidateQueryData = Bundle(),
                                            isSystemProviderRequired = false,
                                            displayInfo =
                                            CreateCredentialRequest.DisplayInfo("userid", "username"),
                                            origin = origin,
                                        ),
                                        callingAppInfo,
                                    )
                                if (Build.VERSION.SDK_INT >= 34) { // TODO: b/361100869 use the official Jetpack api
                                    putExtra(
                                        "android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST",
                                        android.service.credentials.CreateCredentialRequest(
                                            android.service.credentials.CallingAppInfo(
                                                providerRequest.callingAppInfo.packageName,
                                                providerRequest.callingAppInfo.signingInfo,
                                                origin,
                                            ),
                                            providerRequest.callingRequest.type,
                                            Bundle(providerRequest.callingRequest.credentialData),
                                        ),
                                    )
                                    putExtra("androidx.credentials.registry.provider.extra.CREDENTIAL_ID", "0")
                                } else {
                                    val requestBundle = ProviderCreateCredentialRequest.asBundle(providerRequest)
                                    requestBundle.putString(
                                        "androidx.credentials.registry.provider.extra.CREDENTIAL_ID",
                                        "0",
                                    )
                                    putExtra("android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST", requestBundle)
                                }
                            },
                            1111
                        )
                        return
                    }
                    val selectedEntryId = JSONObject(entryId!!)
                    val providerIdx = selectedEntryId.getInt("provider_idx")
                    val selectedId = selectedEntryId.getString("id")

                    val response = processDigitalCredentialOption(
                        digitalCredentialRequestOptions,
                        providerIdx,
                        selectedId,
                        origin
                    )

                    val biometricPrompt = BiometricPrompt(
                        this@GetCredentialActivity,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationFailed() {
                                super.onAuthenticationFailed()
                                Log.d(TAG, "onAuthenticationFailed")
                            }

                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                Log.d(TAG, "onAuthenticationSucceeded")

                                PendingIntentHandler.setGetCredentialResponse(
                                    resultData, GetCredentialResponse(
                                        // This is a temporary solution until Chrome migrate to use
                                        // the top level DC DigitalCredential json structure.
                                        // Long term, this should be replaced by a simple
                                        // `DigitalCredential(response.responseJson)` call.
                                        CustomCredential(
                                            DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
                                            Bundle().apply {
                                                putString(
                                                    "androidx.credentials.BUNDLE_KEY_REQUEST_JSON",
                                                    response.responseJson
                                                )
                                            }
                                        )
                                    )
                                )

                                setResult(RESULT_OK, resultData)
                                finish()
                            }

                            override fun onAuthenticationError(
                                errorCode: Int,
                                errString: CharSequence
                            ) {
                                Log.e(TAG, "onAuthenticationError $errorCode $errString")
                                PendingIntentHandler.setGetCredentialException(
                                    resultData,
                                    GetCredentialUnknownException()
                                )
                                setResult(RESULT_OK, resultData)
                                finish()
                            }
                        })
                    Log.d(TAG, "authenticating")
                    biometricPrompt.authenticate(
                        BiometricPrompt.PromptInfo.Builder()
                            .setTitle(response.authenticationTitle)
                            .setSubtitle(response.authenticationSubtitle)
                            .setConfirmationRequired(false)
                            .setStrongOrDeviceAuthenticators(this@GetCredentialActivity)
                            .build()
                    )
                    return
                } catch (e: Exception) {
                    Log.e(TAG, "exception", e)
                    PendingIntentHandler.setGetCredentialException(
                        resultData,
                        GetCredentialUnknownException()
                    )
                    setResult(RESULT_OK, resultData)
                    finish()
                }
            }
        }
        Log.w(TAG, "No request to handle, terminating")
        finish()
    }

    data class DigitalCredentialResult(
        val responseJson: String,
        val authenticationTitle: CharSequence,
        val authenticationSubtitle: CharSequence?
    )

    @Serializable
    data class DigitalCredentialRequestOptions(
        val providers: List<DigitalCredentialRequest>
    )

    @Serializable
    data class DigitalCredentialRequest(
        val protocol: String,
        val request: String
    )

    private fun processDigitalCredentialOption(
        digitalCredentialRequestOptions: DigitalCredentialRequestOptions,
        providerIdx: Int,
        selectedID: String,
        origin: String
    ): DigitalCredentialResult {
        val selectedCredential = CmWalletApplication.credentialRepo.getCredential(selectedID)
            ?: throw RuntimeException("Selected credential not found")

        Log.i(
            "GetCredentialActivity",
            "digitalCredentialRequestOptions $digitalCredentialRequestOptions"
        )

        val provider = digitalCredentialRequestOptions.providers[providerIdx]

        Log.i(
            "GetCredentialActivity",
            "processDigitalCredentialOption protocol ${provider.protocol}"
        )
        when (provider.protocol) {
            "openid4vp" -> {
                val openId4VPRequest = OpenId4VP(provider.request, computeClientId(request!!.callingAppInfo))
                Log.i("GetCredentialActivity", "nonce ${openId4VPRequest.nonce}")
                val matchedCredential =
                    openId4VPRequest.performQueryOnCredential(selectedCredential)
                Log.i("GetCredentialActivity", "matchedCredential $matchedCredential")



                return createOpenID4VPResponse(
                    openId4VPRequest,
                    origin,
                    selectedCredential,
                    matchedCredential
                );

            }

            else -> throw IllegalArgumentException()
        }
    }
}

/**
 * Returns biometric Strong only if it is available. Otherwise, also allows device credentials.
 */
fun BiometricPrompt.PromptInfo.Builder.setStrongOrDeviceAuthenticators(context: Context): BiometricPrompt.PromptInfo.Builder {
    val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
    val biometricManager = BiometricManager.from(context)
    if (biometricManager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS) {
        this.setAllowedAuthenticators(authenticators).setNegativeButtonText("Cancel")
    } else {
        this.setAllowedAuthenticators(
            authenticators or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
    }
    return this
}

