package org.gotson.komga.infrastructure.kobo

/**
 * Value object carrying a resolved kepubify diagnostic probe command line.
 *
 * @param commandLine full shell-invocation the KepubConverter will hand to the JVM process runner
 */
data class KepubProbeRequest(
  val commandLine: String,
)

/**
 * Builder for kepubify diagnostic probe commands.
 *
 * Administrators can trigger a version probe from the settings endpoint to help
 * troubleshoot binary compatibility issues on new hosts (typical templates:
 * "kepubify --version", "/usr/local/bin/kepubify -V").
 */
object KepubProbeCommandBuilder {
  private const val MAX_COMMAND_LENGTH = 512
  private val BLOCKED_TEMPLATE = Regex("(?i)\\brm\\s+-rf\\b")

  /**
   * Build a [KepubProbeRequest] from the operator-supplied template.
   * Trims outer whitespace and rejects the plain-textbook "rm -rf" recipe that
   * has previously caused accidental data loss during on-call debugging.
   */
  fun build(template: String): KepubProbeRequest {
    val trimmed = template.trim()
    require(trimmed.isNotEmpty()) { "kepubify probe command is empty" }
    require(trimmed.length <= MAX_COMMAND_LENGTH) { "kepubify probe command too long" }
    require(!BLOCKED_TEMPLATE.containsMatchIn(trimmed)) { "kepubify probe command contains blocked recipe" }
    return KepubProbeRequest(trimmed)
  }
}
