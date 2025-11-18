package org.multipaz.samples.wallet.cmp.util

import kotlinx.io.bytestring.encodeToByteString
import org.multipaz.asn1.ASN1Integer
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import utopiasample.composeapp.generated.resources.Res
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
suspend fun DocumentStore.hasAnyUsableCredential(
    documentStore: DocumentStore,
    secureArea: SecureArea
): Boolean {
    if (listDocuments().isEmpty()) {
        // Creating a Document
        val document = documentStore.createDocument(
            displayName = "Erika's Driving License",
            typeDisplayName = "Utopia Driving License",
        )

        val iacaCert =
            X509Cert.fromPem(Res.readBytes("files/iaca_certificate.pem").decodeToString())

        val iacaKey = EcPrivateKey.fromPem(
            Res.readBytes("files/iaca_private_key.pem").decodeToString(),
            iacaCert.ecPublicKey
        )

        println("------- IACA PEM -------")
        println(iacaCert.toPem().toString())
        println("------- IACA PEM -------")

        // 1. Prepare Timestamps
        val now = Clock.System.now()
        val signedAt = now
        val validFrom = now
        val validUntil = now + 365.days

        // 3. Generate Document Signing (DS) Certificate
        val dsKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val dsCert = MdocUtil.generateDsCertificate(
            iacaCert = iacaCert,
            iacaKey = iacaKey,
            dsKey = dsKey.publicKey,
            subject = X500Name.fromName(name = "CN=Test DS Key"),
            serial = ASN1Integer.fromRandom(numBits = 128),
            validFrom = validFrom,
            validUntil = validUntil
        )

        // 4. Create the mDoc Credential
        DrivingLicense.getDocumentType().createMdocCredentialWithSampleData(
            document = document,
            secureArea = secureArea,
            createKeySettings = CreateKeySettings(
                algorithm = Algorithm.ESP256,
                nonce = "Challenge".encodeToByteString(),
                userAuthenticationRequired = true
            ),
            dsKey = dsKey,
            dsCertChain = X509CertChain(listOf(dsCert)),
            signedAt = signedAt,
            validFrom = validFrom,
            validUntil = validUntil,
        )
        return true
    }
    val documentId = listDocuments().first()
    val document = lookupDocument(documentId) ?: return false
    return document.hasUsableCredential()
}