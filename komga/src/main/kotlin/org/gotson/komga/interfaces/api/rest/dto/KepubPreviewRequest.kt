package org.gotson.komga.interfaces.api.rest.dto

/**
 * Request envelope for the kepub preview endpoint.
 *
 * @param bookId identifier of the source book to convert
 * @param kepubifyFlag optional additional flag forwarded to kepubify for preview conversions
 */
data class KepubPreviewRequest(
  val bookId: String,
  val kepubifyFlag: String? = null,
)
