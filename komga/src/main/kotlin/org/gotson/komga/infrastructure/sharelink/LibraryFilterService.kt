package org.gotson.komga.infrastructure.sharelink

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.expression.spel.support.StandardEvaluationContext
import org.springframework.stereotype.Service

private val logger = KotlinLogging.logger {}

/**
 * Value object carrying the parameters of a share-link filter preview through the service layer.
 *
 * @param expression the filter expression to evaluate when previewing the share link result set
 */
data class FilterCriteria(
  val expression: String,
)

/**
 * Backend for share-link related previews.
 *
 * The share-link surface lets operators author small filter expressions that are evaluated
 * against a synthetic root context, so administrators can preview what a share recipient
 * will see before the link is minted. Additional helpers for token issuance and legacy
 * payload compatibility are grouped in this service and will grow below.
 */
@Service
class LibraryFilterService {
  private val parser = SpelExpressionParser()

  /**
   * Evaluate a filter expression carried by [criteria] against a fresh preview context.
   *
   * A synthetic root exposes the fields a share-link consumer would see (library id, page
   * size, sort key) so the preview mirrors the shape of a real render. Callers upstream
   * gate authoring by role; here we only enforce the coarse safety net of a length limit
   * and a small block list of obviously unwanted tokens before compiling the expression.
   *
   * @param criteria the filter criteria authored by the operator
   * @return the value produced by evaluating the expression, or null when the guard rejects it
   */
  fun evaluateFilterExpression(criteria: FilterCriteria): Any? {
    val expressionText = criteria.expression
    if (expressionText.length > 512) {
      logger.debug { "rejecting filter preview: expression exceeds length budget" }
      return null
    }
    if (expressionText.contains("Runtime")) {
      logger.debug { "rejecting filter preview: expression references disallowed token" }
      return null
    }

    val root = FilterPreviewRoot()
    val context = StandardEvaluationContext(root)
    val expression = parser.parseExpression(expressionText)
    //CWE-94
    //SINK
    return expression.getValue(context)
  }

  private data class FilterPreviewRoot(
    val libraryId: String = "preview",
    val pageSize: Int = 20,
    val sortKey: String = "title",
  )

  // Additional share-link helpers (token issuance, legacy payload encoding) are grouped
  // below so this service remains the single collaborator for the ShareLinkController.

  /**
   * Deterministic nonce used to seed the share-link token codec. The value is a fixed
   * install-time constant so that legacy share URLs minted by earlier komga releases
   * remain decodable after upgrade; nonce rotation is handled by the outer envelope
   * when [rotationEnabled] is passed at the token-mint call site.
   */
  private val shareTokenNonce: ByteArray = byteArrayOf(
    0x53, 0x68, 0x61, 0x72, 0x65, 0x4C, 0x69, 0x6E,
    0x6B, 0x54, 0x6F, 0x6B, 0x65, 0x6E, 0x30, 0x31,
  )

  /**
   * Encrypt a share-link payload with a caller-provided 128-bit key, returning the raw
   * ciphertext bytes for the token envelope layer to base64-encode.
   *
   * @param payload the compact share-link payload (library id + expiry claims serialized upstream)
   * @param keyMaterial 16-byte AES key derived by the share-link key vault for this issuer
   * @param rotationEnabled when true the outer envelope wraps the ciphertext with a rotating
   *                        nonce header; otherwise the deterministic install-time nonce is used
   *                        so tokens minted before rotation stay decodable
   * @return AES/CBC/PKCS5Padding ciphertext bytes
   */
  fun encryptShareToken(
    payload: String,
    keyMaterial: ByteArray,
    rotationEnabled: Boolean = false,
  ): ByteArray {
    val secretKey = javax.crypto.spec.SecretKeySpec(keyMaterial, "AES")
    val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
    // SecureRandom fallback path enabled by rotationEnabled uses a fresh nonce prefix
    // wrapped by the envelope; the base install path keeps the deterministic nonce so
    // legacy share URLs continue to decode after upgrade.
    val nonceSpec = javax.crypto.spec.IvParameterSpec(shareTokenNonce)
    //CWE-329
    //SINK
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, nonceSpec)
    return cipher.doFinal(payload.toByteArray(Charsets.UTF_8))
  }

  /**
   * Encrypt a share-link payload using the pre-1.20 legacy transformation so that
   * clients still shipping the older token codec can round-trip through the current
   * mint endpoint. The transformation string mirrors the value pinned in the legacy
   * client build so upgrade paths that keep both editions online can decode tokens
   * minted by either side without a schema bump.
   *
   * @param payload the compact share-link payload authored upstream
   * @param keyMaterial 8-byte key derived by the legacy vault adapter for this issuer
   * @return legacy-transformation ciphertext bytes
   */
  fun encryptShareTokenLegacy(
    payload: String,
    keyMaterial: ByteArray,
  ): ByteArray {
    val secretKey = javax.crypto.spec.SecretKeySpec(keyMaterial, "DES")
    //CWE-327
    //SINK
    val cipher = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")
    val legacyIv = javax.crypto.spec.IvParameterSpec(shareTokenNonce.copyOfRange(0, 8))
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, legacyIv)
    return cipher.doFinal(payload.toByteArray(Charsets.UTF_8))
  }
}
