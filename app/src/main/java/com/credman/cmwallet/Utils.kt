package com.credman.cmwallet

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

fun loadECPrivateKey(keyDer: ByteArray): PrivateKey {
    val devicePrivateKeySpec = PKCS8EncodedKeySpec(keyDer)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePrivate(devicePrivateKeySpec)!!
}

fun intToBigEndianByteArray(source: Int): ByteArray {
    val buffer = ByteBuffer.allocate(Int.SIZE_BYTES)
    buffer.order(ByteOrder.BIG_ENDIAN)
    buffer.putInt(source)
    return buffer.array()
}

fun BigInteger.toFixedByteArray(requiredLength: Int): ByteArray {
    val bytes = this.toByteArray()
    var offset = 0
    var pad = 0
    var length = bytes.size
    if (length == requiredLength) {
        return bytes
    }
    val fixedArray = ByteArray(requiredLength)
    if (length > requiredLength) {
        offset = length - requiredLength
        length = requiredLength
    } else {
        pad = requiredLength - length
    }
    bytes.copyInto(fixedArray, pad, offset, offset + length)
    return fixedArray
}

fun PublicKey.toJWK(): JsonElement {
    when (this) {
        is ECPublicKey -> {
            val x = this.w.affineX.toFixedByteArray(32).toBase64UrlNoPadding()
            val y = this.w.affineY.toFixedByteArray(32).toBase64UrlNoPadding()
            return Json.encodeToJsonElement(
                mapOf(
                    Pair("kty", "EC"),
                    Pair("crv", "P-256"),
                    Pair("x", x),
                    Pair("y", y)
                )
            )
        }

        else -> {
            throw IllegalArgumentException("Only support EC Keys for now")
        }
    }
}

@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.toBase64UrlNoPadding(): String {
    return Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(this)
}

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeBase64UrlNoPadding(): ByteArray {
    return Base64.UrlSafe.withPadding(kotlin.io.encoding.Base64.PaddingOption.ABSENT).decode(this)
}

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeBase64(): ByteArray {
    return Base64.decode(this)
}

fun createJWTES256(
    header: JsonElement,
    payload: JsonElement,
    privateKey: PrivateKey
): String {
    val headerB64 = Json.encodeToString(header).encodeToByteArray().toBase64UrlNoPadding()
    val payloadB64 = Json.encodeToString(payload).encodeToByteArray().toBase64UrlNoPadding()
    val signatureDer = Signature.getInstance("SHA256withECDSA").run {
        initSign(privateKey)
        update(("$headerB64.$payloadB64").encodeToByteArray())
        sign()
    }
    return "$headerB64.$payloadB64.${convertDerToRaw(signatureDer).toBase64UrlNoPadding()}"
}

fun convertDerToRaw(signature: ByteArray): ByteArray {
    val ret = ByteArray(64)

    var rOffset = 4
    if ((signature[1].toInt() and 0x80) != 0) {
        rOffset += signature[1].toInt() and 0x7f
    }

    var rLen = signature[rOffset - 1].toInt() and 0xFF
    var rPad = 0

    if (rLen > 32) {
        rOffset += (rLen - 32)
        rLen = 32
    } else {
        rPad = 32 - rLen
    }
    signature.copyInto(ret, rPad, rOffset, rOffset + rLen)

    var sOffset = rOffset + rLen + 2
    var sLen = signature[sOffset - 1].toInt() and 0xFF
    var sPad = 0

    if (sLen > 32) {
        sOffset += (sLen - 32)
        sLen = 32
    } else {
        sPad = 32 - sLen
    }
    signature.copyInto(ret, 32 + sPad, sOffset, sOffset + sLen)

    return ret
}