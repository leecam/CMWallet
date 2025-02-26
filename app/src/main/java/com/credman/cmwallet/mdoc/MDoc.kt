package com.credman.cmwallet.mdoc

import com.credman.cmwallet.cbor.CborTag
import com.credman.cmwallet.cbor.cborDecode
import com.credman.cmwallet.cbor.cborEncode
import com.credman.cmwallet.convertDerToRaw
import java.security.PrivateKey
import java.security.Signature

fun createSessionTranscript(handover: Any): List<Any?> {
    return listOf(
        null,
        null,
        handover
    )
}

class MDoc(
    issuerSigned: ByteArray,
) {
    private val issuerSignedDict: Map<*, *> by lazy {
        cborDecode(issuerSigned) as Map<*, *>
    }

    val issuerSignedNamespaces: Map<String, Map<String, Any?>> by lazy {
        val map = mutableMapOf<String, Map<String, Any?>>()
        if ("nameSpaces" in issuerSignedDict) {
            val namespaces = issuerSignedDict["nameSpaces"] as Map<String, List<CborTag>>
            namespaces.forEach { (namespace, elements) ->
                map[namespace] = elements.associate { tag ->
                    val element = cborDecode(tag.item as ByteArray) as Map<*, *>
                    Pair(element["elementIdentifier"] as String, element["elementValue"])
                }
            }
        }
        map
    }
}

//fun toCredentialItem(
//    issuerSigned: ByteArray,
//    deviceKey: PrivateKey,
//    credentialConfiguration: CredentialConfiguration,
//): CredentialItem {
//    require(credentialConfiguration is CredentialConfigurationMDoc) { "Credential configuration should be" }
//    val issuerSignedDict = cborDecode(issuerSigned) as Map<*, *>
//    val doctype = credentialConfiguration.doctype
//    val claims = credentialConfiguration.claims
//    val issuerSignedNamespaces = (issuerSignedDict.toMutableMap()["nameSpaces"] as Map<String, *>)
//    val nameSpaces: Map<String, MdocNameSpace> = issuerSignedNamespaces.mapValues { (key, value) ->
//        Log.d(TAG, "Processing namespacedData for namespace $key")
//        val issuerSignedElements = value as List<*>
//        Log.d(TAG, "Keys ${claims?.keys}")
//        val namespacedClaims = claims!![key]!!
//        val namespacedData = mutableMapOf<String, MdocField>()
//        issuerSignedElements.forEach { element ->
//            if (element is CborTag) {
//                val elementDict = cborDecode(element.item as ByteArray) as Map<*, *>
//                val elementIdentifier = elementDict[ELEMENT_IDENTIFYIER] as String
//                val elementValue = elementDict[ELEMENT_VALUE] as Any
//                val elementDisplay =
//                    namespacedClaims[elementIdentifier]?.display?.firstOrNull()
//                if (elementDisplay?.name == null) {
//                    Log.w(
//                        TAG,
//                        "Skipping element $elementIdentifier because it doesn't have a display value"
//                    )
//                } else {
//                    namespacedData[elementIdentifier] = MdocField(
//                        value = elementValue,
//                        display = elementDisplay.name,
//                        displayValue = elementValue.toString() // TODO: This technically isn't right but we can't get this display value from elsewhere.
//                    )
//                }
//            }
//        }
//        Log.d(TAG, "Added namespacedData for namespace $key: $namespacedData")
//        return@mapValues MdocNameSpace(data = namespacedData)
//    }
//    val cred = MdocCredential(
//        docType = doctype,
//        nameSpaces = nameSpaces,
//        deviceKey = deviceKey,
//        issuerSigned = issuerSigned
//    )
//
//    val regex = "image/.*,".toRegex()
//    val title = credentialConfiguration.display?.firstOrNull()?.name
//    val subtitle = credentialConfiguration.display?.firstOrNull()?.description
//    val itemIcon = credentialConfiguration.display?.firstOrNull()?.backgroundImage?.let {
//        val imageUri = Uri.parse(it.uri)
//        require(imageUri.scheme == "data") { "only image data scheme is supported for now" }
//        val ssp = Uri.parse(it.uri).schemeSpecificPart
//        ssp.replace(regex, "")
//    }
//    val credMetadata = when (doctype) {
//        PAYMENT_CARD_DOC_TYPE -> PaymentMetadata(
//            title = title ?: "Payment Card",
//            subtitle = subtitle,
//            icon = itemIcon,
//            cardNetworkArt = null,
//        )
//
//        else -> VerificationMetadata(
//            title = title ?: "Card",
//            subtitle = subtitle,
//            icon = itemIcon
//        )
//    }
//
//    return CredentialItem(
//        id = 0L.toString(), // Auto-gen
//        credential = cred,
//        metadata = credMetadata,
//    )
//}

fun filterIssuerSigned(
    issuerSigned: ByteArray,
    requiredElements: Map<String, List<String>>
): ByteArray {
    val issuerSignedDict = cborDecode(issuerSigned) as Map<*, *>
    val ret = issuerSignedDict.toMutableMap()
    val namespaces = ret["nameSpaces"] as Map<*, *>
    val newNamespaces = mutableMapOf<String, List<CborTag>>()
    requiredElements.forEach { (namespace, requiredElements) ->
        if (namespaces.contains(namespace)) {
            val newElements = mutableListOf<CborTag>()
            requiredElements.forEach { requiredElement ->
                val elements = namespaces[namespace] as List<*>
                elements.forEach { element ->
                    if (element is CborTag) {
                        val elementDict = cborDecode(element.item as ByteArray) as Map<*, *>
                        val elementIdentifier = elementDict[ELEMENT_IDENTIFYIER] as String
                        if (elementIdentifier == requiredElement) {
                            newElements.add(element)
                        }
                    }
                }
            }
            if (newElements.size > 0) {
                newNamespaces[namespace] = newElements
            }
        }
    }
    ret["nameSpaces"] = newNamespaces
    return cborEncode(ret)
}

fun generateDeviceResponse(
    doctype: String,
    issuerSigned: ByteArray,
    devicePrivateKey: PrivateKey,
    sessionTranscript: List<Any?>,
    deviceNamespaces: Map<String, Any> = emptyMap()
): ByteArray {
    val deviceNamespacesTag = CborTag(24, cborEncode(deviceNamespaces))

    val deviceAuthentication = listOf<Any>(
        "DeviceAuthentication",
        sessionTranscript,
        doctype,
        deviceNamespacesTag
    )

    val deviceAuthenticationBytes = cborEncode(CborTag(24, cborEncode(deviceAuthentication)))

    val protected = cborEncode(mapOf(1 to -7))
    val sigStructure = listOf<Any>(
        "Signature1",
        protected,
        byteArrayOf(),
        deviceAuthenticationBytes
    )
    val signatureDer = Signature.getInstance("SHA256withECDSA").run {
        initSign(devicePrivateKey)
        update(cborEncode(sigStructure))
        sign()
    }

    val signature = convertDerToRaw(signatureDer)

    val deviceSignature = listOf<Any?>(
        protected,
        emptyMap<Int, Int>(),
        null,
        signature
    )

    val deviceSigned = mapOf(
        "nameSpaces" to deviceNamespacesTag,
        "deviceAuth" to mapOf("deviceSignature" to deviceSignature)
    )
    val document = mapOf(
        "docType" to doctype,
        "issuerSigned" to cborDecode(issuerSigned),
        "deviceSigned" to deviceSigned
    )
    val deviceResponse = mapOf(
        "version" to "1.0",
        "documents" to listOf(document),
        "status" to 0
    )
    return cborEncode(deviceResponse)
}


internal const val ELEMENT_IDENTIFYIER = "elementIdentifier"
internal const val ELEMENT_VALUE = "elementValue"