package kz.gov.pki.ncalayer

import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.jar.JarFile
import javax.security.auth.x500.X500Principal
import java.io.File
import javax.swing.JFileChooser
import javax.swing.filechooser.FileFilter
import java.awt.event.ActionListener
import java.lang.NullPointerException

private val HEX_CHARS = "0123456789abcdef".toCharArray()

fun ByteArray.toHex(): String {
	val result = StringBuffer()

	forEach {
		val octet = it.toInt()
		val firstIndex = (octet and 0xF0).ushr(4)
		val secondIndex = octet and 0x0F
		result.append(HEX_CHARS[firstIndex])
		result.append(HEX_CHARS[secondIndex])
	}

	return result.toString()
}

fun main(args: Array<String>) {
	val bundleChooser = JFileChooser()
	bundleChooser.addActionListener {
		if (it.actionCommand == JFileChooser.APPROVE_SELECTION) {
			val fileChooser = it.source as JFileChooser
			processJar(fileChooser.selectedFile.absolutePath)
		}
	}
	bundleChooser.showOpenDialog(null)
}

fun processJar(bundle: String) {
	val file = File(bundle)
	val logFile = File(file.parentFile, file.nameWithoutExtension + ".txt")
	val digestAlg = "SHA-256"
	logFile.writer().use { w ->
		w.appendln("Processing $file ...")
		try {
			JarFile(bundle, true).use { jf ->
				w.appendln("-----[Begin manifest]-----")
				jf.manifest.mainAttributes.forEach {
					w.write("${it.key}: ${it.value}\n")
				}
				w.appendln("-----[End manifest]-----")

				jf.entries().asSequence().forEach { e ->
					jf.getInputStream(e).use {
						it.readBytes()
					}
				}
				val signers = jf.getJarEntry(JarFile.MANIFEST_NAME).codeSigners
				if (signers == null) {
					throw NullPointerException("Error! ---------> Jar is not signed!")
				}
				if (signers.size > 1) {
					w.appendln("Warning! ---------> Multiple signers!");
				}
				signers.forEach {
					w.appendln("-----[Signer]-----")
					val certs = it.signerCertPath.certificates
					if (certs.size <= 1) {
						w.appendln("Warning! ---------> Incomplete certificate chain!")
					}
					certs.forEach {
						it as X509Certificate
						w.appendln(it.subjectX500Principal.toString())
						w.appendln("${it.notBefore} - ${it.notAfter}")
						w.appendln("Serial Number: ${it.serialNumber.toByteArray().toHex()}")
						MessageDigest.getInstance(digestAlg).digest(it.encoded).apply { w.appendln("$digestAlg Certificate Digest: ${this.toHex()}") }
					}
				}

			}
			MessageDigest.getInstance(digestAlg).digest(file.readBytes()).apply {
				w.appendln("-----[$digestAlg JAR Digest]-----\n${this.toHex()}")
			}
		} catch (e: Exception) {
			w.appendln(e.message)
		}
	}
}