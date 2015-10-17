/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * SignedToken containing a TimeStamp.
 *
 * @version $Revision: 1824 $ - $Date: 2013-03-28 15:57:23 +0100 (Thu, 28 Mar 2013) $
 */
public class TimestampToken extends Token {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampToken.class);

	private final TimeStampToken timeStamp;

	private TimestampType timeStampType;

	private int dssId;

	private CAdESCertificateSource wrappedSource;

	private X500Principal issuerX500Principal;

	private boolean messageImprintData;

	private Boolean messageImprintIntact = null;

	private String signedDataMessage = "";

	private List<TimestampReference> timestampedReferences;

	private List<TimestampInclude> timestampIncludes;

	/**
	 * Defines for archive timestamp its type.
	 */
	private ArchiveTimestampType archiveTimestampType;

	/**
	 * This attribute is used for XAdES timestamps. It indicates the canonicalization method used before creating the digest.
	 */
	private String canonicalizationMethod;

	/**
	 * This attribute is used only with XAdES timestamps. It represents the hash code of the DOM element containing the timestamp. It's an internal attribute which allows to
	 * unambiguously identify a timestamp.
	 */
	private int hashCode;

	/**
	 * Constructor with an indication of the timestamp type. The default constructor for {@code TimestampToken}.
	 *
	 * @param timeStamp {@code TimeStampToken}
	 * @param type      {@code TimestampType}
	 * @param certPool  {@code CertificatePool} which is used to identify the signing certificate of the timestamp
	 */
	public TimestampToken(final TimeStampToken timeStamp, final TimestampType type, final CertificatePool certPool) {

		this.timeStamp = timeStamp;
		this.timeStampType = type;
		this.extraInfo = new TokenValidationExtraInfo();
		wrappedSource = new CAdESCertificateSource(timeStamp, certPool);
		final Collection<CertificateToken> certs = wrappedSource.getCertificates();
		for (final CertificateToken certificateToken : certs) {

			final byte[] encoded = certificateToken.getEncoded();
			final Certificate certificate = Certificate.getInstance(encoded);
			final X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificate);
			if (timeStamp.getSID().match(x509CertificateHolder)) {

				boolean valid = isSignedBy(certificateToken);
				if (valid) {
					break;
				}
			}
		}
		final byte[] digest = DSSUtils.digest(DigestAlgorithm.MD5, DSSUtils.getEncoded(timeStamp));
		final String base64Encoded = DSSUtils.base64Encode(digest);
		dssId = base64Encoded.hashCode();
	}

	@Override
	public int getDSSId() {
		return dssId;
	}

	@Override
	public String getAbbreviation() {

		return timeStampType.name() + ": " + getDSSId() + ": " + DSSUtils.formatInternal(timeStamp.getTimeStampInfo().getGenTime());
	}

	/**
	 * This method returns the issuing certificate's distinguished subject name.
	 *
	 * @return {@code X500Principal} representing the issuing certificate's distinguished subject name.
	 */
	public X500Principal getIssuerX500Principal() {

		return issuerX500Principal;
	}

	@Override
	public boolean isSignedBy(final CertificateToken issuerToken) {

		if (this.issuerToken != null) {

			return this.issuerToken.equals(issuerToken);
		}
		final TimestampValidation timestampValidation = validateTimestampToken(timeStamp, issuerToken);
		final TimestampValidity timestampValidity = timestampValidation.getValidity();
		signatureInvalidityReason = timestampValidity.name();
		signatureValid = timestampValidation.isValid();
		if (signatureValid) {

			this.issuerToken = issuerToken;

			issuerX500Principal = issuerToken.getSubjectX500Principal();
			final String algorithm = issuerToken.getPublicKey().getAlgorithm();
			final EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(algorithm);
			final AlgorithmIdentifier hashAlgorithm = timeStamp.getTimeStampInfo().getHashAlgorithm();
			final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(hashAlgorithm.getAlgorithm());
			algorithmUsedToSignToken = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
		}
		return signatureValid;
	}

	private TimestampValidation validateTimestampToken(final TimeStampToken timeStampToken, final CertificateToken issuerToken) {

		TimestampValidity timestampValidity;
		try {

			final JcaSimpleSignerInfoVerifierBuilder verifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
			final X509Certificate x509Certificate = issuerToken.getCertificate();
			final SignerInformationVerifier verifier = verifierBuilder.build(x509Certificate);
			timeStampToken.validate(verifier);
			timestampValidity = TimestampValidity.VALID;
		} catch (IllegalArgumentException e) {
			timestampValidity = TimestampValidity.NO_SIGNING_CERTIFICATE;
			LOG.error("No signing certificate for timestamp token: " + e);
		} catch (TSPValidationException e) {
			timestampValidity = TimestampValidity.NOT_VALID_SIGNATURE;
		} catch (TSPException e) {
			timestampValidity = TimestampValidity.NOT_VALID_STRUCTURE;
		} catch (OperatorCreationException e) {
			timestampValidity = TimestampValidity.NOT_VALID_STRUCTURE;
		}
		final TimestampValidation timestampValidation = new TimestampValidation(timestampValidity);
		return timestampValidation;
	}

	/**
	 * Checks if the {@code TimeStampToken} matches the signed data.
	 *
	 * @param data the array of {@code byte} representing the timestamped data
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final byte[] data) {

		try {

			messageImprintData = data != null;
			final TimeStampTokenInfo timeStampInfo = timeStamp.getTimeStampInfo();
			final ASN1ObjectIdentifier hashAlgorithm = timeStampInfo.getHashAlgorithm().getAlgorithm();
			final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(hashAlgorithm);

			final byte[] computedDigest = DSSUtils.digest(digestAlgorithm, data);
			final byte[] timestampDigest = timeStampInfo.getMessageImprintDigest();
			messageImprintIntact = Arrays.equals(computedDigest, timestampDigest);
			if (!messageImprintIntact) {

				LOG.error("Extracted data from the document: {}", DSSUtils.base64Encode(data));//, 200));
				LOG.error("Computed digest ({}) on the extracted data from the document : {}", digestAlgorithm, DSSUtils.base64Encode(computedDigest));
				LOG.error("Digest present in TimestampToken: {}", DSSUtils.base64Encode(timestampDigest));
				LOG.error("Digest in TimestampToken matches digest of extracted data from document: {}", messageImprintIntact);
			}
		} catch (DSSException e) {

			messageImprintIntact = false;
			signedDataMessage = "Timestamp digest problem: " + e.getMessage();
		}
		return messageImprintIntact;
	}

	/**
	 * Retrieves the type of the timestamp token.
	 *
	 * @return {@code TimestampType}
	 */
	public TimestampType getTimeStampType() {

		return timeStampType;
	}

	/**
	 * Retrieves the timestamp generation time.
	 *
	 * @return {@code Date}
	 */
	public Date getGenerationTime() {

		return timeStamp.getTimeStampInfo().getGenTime();
	}

	/**
	 * Retrieves the {@code DigestAlgorithm} used to generate the digest value to timestamp.
	 *
	 * @return {@code DigestAlgorithm}
	 */
	public DigestAlgorithm getSignedDataDigestAlgo() {

		final ASN1ObjectIdentifier oid = timeStamp.getTimeStampInfo().getHashAlgorithm().getAlgorithm();
		return DigestAlgorithm.forOID(oid);
	}

	/**
	 * Retrieves the encoded signed data digest value.
	 *
	 * @return base 64 encoded {@code String}
	 */
	public String getEncodedSignedDataDigestValue() {

		final byte[] messageImprintDigest = timeStamp.getTimeStampInfo().getMessageImprintDigest();
		return DSSUtils.base64Encode(messageImprintDigest);
	}

	/**
	 * @return true if the message imprint data was found, false otherwise
	 */
	public Boolean isMessageImprintDataFound() {

		return messageImprintData;
	}

	/**
	 * The method {@code matchData} must be invoked previously.
	 *
	 * @return true if the message imprint data is intact, false otherwise
	 */
	public Boolean isMessageImprintDataIntact() {

		if (messageImprintIntact == null) {
			throw new DSSException("Invoke matchData(byte[] data) method before!");
		}
		return messageImprintIntact;
	}

	/**
	 * @return {@code List} of {@code TimestampReference}s
	 */
	public List<TimestampReference> getTimestampedReferences() {

		return timestampedReferences;
	}

	/**
	 * This method is used to set the timestamped references. The reference can be the digest value of the certificate or of the revocation data. The same references can be
	 * timestamped by different timestamps.
	 *
	 * @param timestampedReferences {@code List} of {@code TimestampReference}
	 */
	public void setTimestampedReferences(final List<TimestampReference> timestampedReferences) {

		this.timestampedReferences = timestampedReferences;
	}

	/**
	 * @return {@code ArchiveTimestampType} in the case of an archive timestamp, {@code null} otherwise
	 */
	public ArchiveTimestampType getArchiveTimestampType() {
		return archiveTimestampType;
	}

	/**
	 * Archive timestamps can be of different sub type.
	 *
	 * @param archiveTimestampType {@code ArchiveTimestampType}
	 */
	public void setArchiveTimestampType(final ArchiveTimestampType archiveTimestampType) {
		this.archiveTimestampType = archiveTimestampType;
	}

	/**
	 * Applies only fro XAdES timestamps
	 *
	 * @return {@code String} representing the canonicalization method used by the timestamp
	 */
	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	/**
	 * Allows to set the canonicalization method used by the timestamp. Applies only with XAdES timestamps.
	 *
	 * @param canonicalizationMethod {@code String} representing the canonicalization method
	 */
	public void setCanonicalizationMethod(final String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	@Override
	public byte[] getEncoded() {
		return DSSUtils.getEncoded(timeStamp);
	}

	// TODO-Vin (12/09/2014): Comment!
	public List<TimestampInclude> getTimestampIncludes() {
		return timestampIncludes;
	}

	// TODO-Vin (12/09/2014): Comment!
	public void setTimestampIncludes(List<TimestampInclude> timestampIncludes) {
		this.timestampIncludes = timestampIncludes;
	}

	/**
	 * Returns the list of wrapped certificates.
	 *
	 * @return {@code List} of {@code CertificateToken}
	 */
	public List<CertificateToken> getCertificates() {
		return wrappedSource.getCertificates();
	}

	public AttributeTable getUnsignedAttributes() {
		return timeStamp.getUnsignedAttributes();
	}

	/**
	 * Used only with XAdES timestamps.
	 *
	 * @return the hash code of the DOM element containing the timestamp
	 */
	public int getHashCode() {
		return hashCode;
	}

	/**
	 * Used only with XAdES timestamps.
	 *
	 * @param hashCode the hash code of the DOM element containing the timestamp
	 */
	public void setHashCode(final int hashCode) {
		this.hashCode = hashCode;
	}

	@Override
	public String toString(String indentStr) {

		try {

			final StringBuffer out = new StringBuffer();
			out.append(indentStr).append("TimestampToken[signedBy=").append(issuerToken == null ? "?" : issuerToken.getDSSIdAsString());
			out.append(", generated: ").append(DSSUtils.formatInternal(timeStamp.getTimeStampInfo().getGenTime()));
			out.append(" / ").append(timeStampType).append('\n');
			if (signatureValid) {

				indentStr += "\t";
				out.append(indentStr).append("Timestamp's signature validity: VALID").append('\n');
				indentStr = indentStr.substring(1);
			} else {

				if (!signatureInvalidityReason.isEmpty()) {

					indentStr += "\t";
					out.append(indentStr).append("Timestamp's signature validity: INVALID").append(" - ").append(signatureInvalidityReason).append('\n');
					indentStr = indentStr.substring(1);
				}
			}
			indentStr += "\t";
			if (messageImprintIntact != null) {

				if (messageImprintIntact) {

					out.append(indentStr).append("Timestamp MATCHES the signed data.").append('\n');
				} else {

					out.append(indentStr).append("Timestamp DOES NOT MATCH the signed data.").append('\n');
					if (!signedDataMessage.isEmpty()) {

						out.append(indentStr).append("- ").append(signedDataMessage).append('\n');
					}
				}
			}
			indentStr = indentStr.substring(1);
			if (issuerToken != null) {

				indentStr += "\t";
				out.append(issuerToken.toString(indentStr)).append('\n');
				indentStr = indentStr.substring(1);
				out.append(indentStr);
			}
			out.append("]");
			return out.toString();
		} catch (Exception e) {
			return getClass().getName();
		}
	}
}