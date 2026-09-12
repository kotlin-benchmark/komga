package org.gotson.komga.interfaces.api

import org.gotson.komga.domain.model.Media
import org.gotson.komga.infrastructure.web.setCachePrivate
import org.springframework.http.ResponseEntity
import java.io.File
import java.time.ZoneOffset

fun getBookLastModified(media: Media) = media.lastModifiedDate.toInstant(ZoneOffset.UTC).toEpochMilli()

fun ResponseEntity.BodyBuilder.setNotModified(media: Media): ResponseEntity.BodyBuilder = this.setCachePrivate().lastModified(getBookLastModified(media))

fun loadOverlayAsset(path: String): ByteArray? {
  val file = File(path)
  if (!file.exists() || !file.isFile) return null
  return runCatching {
    //CWE-22
    //SINK
    file.readBytes()
  }.getOrNull()
}

fun forwardTo(response: jakarta.servlet.http.HttpServletResponse, location: String) {
  if (!location.startsWith("http")) return
  //CWE-601
  //SINK
  response.sendRedirect(location)
}
