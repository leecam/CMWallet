package com.credman.cmwallet.openid4vp

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

abstract class MatchedClaim()

class MatchedMDocClaim(val namespace: String, val claimName: String) : MatchedClaim()

data class MatchedCredential (
    val id: String,
    val matchedClaims: MutableList<MatchedClaim> = mutableListOf()
)

fun DCQLQuery(query: JSONObject, credentialStore: JSONObject): Map<String, List<MatchedCredential>> {
    require(query.has("credentials")) {"dcql_query must contain a credentials"}
    val credentials = query.getJSONArray("credentials")
    require(credentials.length() == 1) {"Only support returning a single document"}
    val credential = credentials.getJSONObject(0)!!

    require(credential.has("id")) {"dcql_query credential must contain an id"}
    val id = credential.getString(("id"))
    val matchedCredentials = matchCredential(credential, credentialStore.getJSONObject("credentials"))
    Log.i("DCQL", "matchedCredentials $matchedCredentials")
    return mapOf(Pair(id, matchedCredentials))
}

fun matchCredential(credential: JSONObject, credentialStore: JSONObject): List<MatchedCredential> {
    require(credential.has("format")) {"dcql_query credential must contain a format"}

    val matchedCredentials = mutableListOf<MatchedCredential>()


    val format = credential.getString(("format"))

    val meta = credential.opt("meta") as JSONObject?
    val claims = credential.opt("claims") as JSONArray?
    val claimSets = credential.opt("claim_sets") as JSONArray?

    require(!(claims == null && claimSets != null )) {"dcql_query credential must contains claim_sets without claims"}

    // Filter by format
    val candidatesByFormat = credentialStore.opt(format) as JSONObject? ?: return matchedCredentials

    Log.i("DCQL", "candidatesByFormat $candidatesByFormat")

    val candidatesByMeta: JSONArray
    // Filter on the meta
    if (meta != null) {
        when (format) {
            "mso_mdoc" -> {
                val docType = meta.opt("doctype_value") as String? ?: return matchedCredentials
                Log.i("DCQL", "doctype $docType")
                if (candidatesByFormat.has(docType)) {
                    candidatesByMeta = candidatesByFormat.getJSONArray(docType)
                } else {
                    return matchedCredentials
                }

            }
            else -> return matchedCredentials
        }
    } else {
        // TODO: fix the fact that doctype is required at the moment.
        return matchedCredentials
    }

    Log.i("DCQL", "candidatesByMeta $candidatesByMeta")

    if (claims == null) {
        Log.i("DCQL", "Matching without claims")
    } else {
        Log.i("DCQL", "Matching with claims")
        if (claimSets == null) {
            Log.i("DCQL", "Matching without claim_sets")
            for (candidateIdx in 0 until candidatesByMeta.length()) {
                val candidate = candidatesByMeta.getJSONObject(candidateIdx)!!
                val matchedCredential = MatchedCredential(candidate.getString("id"))

                for (claimIdx in 0 until claims.length()) {
                    val claim = claims.getJSONObject(claimIdx)!!
                    val claimValues = claim.opt("values") as JSONArray?
                    when (format) {
                        "mso_mdoc" -> {
                            require(claim.has("namespace")) {"mdoc claim credential must contain namespace"}
                            require(claim.has("claim_name")) {"mdoc claim credential must contain claim_name"}
                            val namespace = claim.getString("namespace")
                            val claimName = claim.getString("claim_name")
                            if (candidate.getJSONObject("namespaces").has(namespace)) {
                                if (candidate.getJSONObject("namespaces").getJSONObject(namespace).has(claimName)) {
                                    matchedCredential.matchedClaims.add(MatchedMDocClaim(namespace, claimName))
                                }
                            }
                        }
                    }
                }
                if (claims.length() == matchedCredential.matchedClaims.size) {
                    matchedCredentials.add(matchedCredential)
                }
            }
        }
    }
    return matchedCredentials
}