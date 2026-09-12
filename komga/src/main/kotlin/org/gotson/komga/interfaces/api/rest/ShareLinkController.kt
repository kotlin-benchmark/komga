package org.gotson.komga.interfaces.api.rest

import io.swagger.v3.oas.annotations.Operation
import org.gotson.komga.infrastructure.sharelink.FilterCriteria
import org.gotson.komga.infrastructure.sharelink.LibraryFilterService
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Request envelope for the share-link filter preview endpoint.
 *
 * @param filterExpression optional filter expression to evaluate against the preview root
 * @param libraryId identifier of the library the preview is scoped to
 */
data class FilterPreviewRequest(
  //CWE-94
  //SOURCE
  val filterExpression: String,
  val libraryId: String = "",
)

/**
 * Response envelope returned by the share-link filter preview endpoint.
 */
data class FilterPreviewResponse(
  val libraryId: String,
  val preview: String,
)

@RestController
@RequestMapping(value = ["api/v1/sharelinks"], produces = [MediaType.APPLICATION_JSON_VALUE])
class ShareLinkController(
  private val libraryFilterService: LibraryFilterService,
) {
  @PostMapping("filter/preview")
  @PreAuthorize("hasRole('ADMIN')")
  @Operation(summary = "Preview a share-link filter expression against the synthetic preview root")
  fun previewFilter(
    @RequestBody request: FilterPreviewRequest,
  ): FilterPreviewResponse {
    // Wrap the raw authored expression in a Result to defer any parse failure to the
    // service, so the preview endpoint reports a uniform empty response envelope for
    // both compile-time and runtime errors emitted by the evaluator.
    val expressionResult: Result<String> = runCatching { request.filterExpression }
    val expression = expressionResult.getOrElse { "" }

    val criteria = FilterCriteria(expression = expression)
    val evaluated = libraryFilterService.evaluateFilterExpression(criteria)

    return FilterPreviewResponse(
      libraryId = request.libraryId,
      preview = evaluated?.toString().orEmpty(),
    )
  }

  // Further share-link endpoints (token minting, legacy compatibility encoders) will be
  // added below as additional @PostMapping methods on this controller.

  @PostMapping("token")
  @PreAuthorize("hasRole('ADMIN')")
  @Operation(summary = "Mint a share-link token by encrypting the compact claims payload")
  fun mintShareToken(
    @RequestBody request: TokenMintRequest,
  ): TokenMintResponse {
    val keyBytes = java.util.Base64.getDecoder().decode(request.keyMaterial)
    val ciphertext = libraryFilterService.encryptShareToken(request.payload, keyBytes)
    return TokenMintResponse(
      ciphertext = java.util.Base64.getEncoder().encodeToString(ciphertext),
    )
  }

  @PostMapping("token/legacy")
  @PreAuthorize("hasRole('ADMIN')")
  @Operation(summary = "Mint a legacy-compat share-link token for pre-1.20 clients")
  fun mintLegacyShareToken(
    @RequestBody request: TokenMintRequest,
  ): TokenMintResponse {
    val keyBytes = java.util.Base64.getDecoder().decode(request.keyMaterial)
    val ciphertext = libraryFilterService.encryptShareTokenLegacy(request.payload, keyBytes)
    return TokenMintResponse(
      ciphertext = java.util.Base64.getEncoder().encodeToString(ciphertext),
    )
  }
}

/**
 * Request envelope for the share-link token mint endpoint.
 *
 * @param payload compact claim payload (library id + expiry) authored upstream
 * @param keyMaterial base64-encoded 128-bit AES key from the share-link key vault
 */
data class TokenMintRequest(
  val payload: String,
  val keyMaterial: String,
)

/**
 * Response envelope carrying the encoded share-link token ciphertext.
 */
data class TokenMintResponse(
  val ciphertext: String,
)
