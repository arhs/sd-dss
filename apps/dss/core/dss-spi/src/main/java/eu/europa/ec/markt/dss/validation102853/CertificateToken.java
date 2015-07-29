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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSPKUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * Whenever the signature validation process encounters an {@link java.security.cert.X509Certificate} a certificateToken is created.<br>
 * This class encapsulates some frequently used information: a certificate comes from a certain context (Trusted List,
 * CertStore, Signature), has revocation data... To expedite the processing of such information, they are kept in cache.
 *
 * @version $Revision: 1837 $ - $Date: 2013-03-14 21:07:50 +0100 (Thu, 14 Mar 2013) $
 */

public class CertificateToken extends Token {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateToken.class);

	public static final String DIGITAL_SIGNATURE = "digitalSignature";
	public static final String NON_REPUDIATION = "nonRepudiation";
	public static final String KEY_ENCIPHERMENT = "keyEncipherment";
	public static final String DATA_ENCIPHERMENT = "dataEncipherment";
	public static final String KEY_AGREEMENT = "keyAgreement";
	public static final String KEY_CERT_SIGN = "keyCertSign";
	public static final String CRL_SIGN = "cRLSign";
	public static final String ENCIPHER_ONLY = "encipherOnly";
	public static final String DECIPHER_ONLY = "decipherOnly";

	/**
	 * Encapsulated X509 certificate.
	 */
	private X509Certificate x509Certificate;

	/**
	 * This array contains the different sources for this certificate.
	 */
	private final List<CertificateSourceType> sources = new ArrayList<CertificateSourceType>();

	/**
	 * If the certificate is part of the trusted list then the the serviceInfo represents the associated trusted service
	 * provider service. Same certificate can be a part of multiple services.
	 */
	private final List<ServiceInfo> associatedTSPS = new ArrayList<ServiceInfo>();

	/**
	 * DSS unique id based on the issuer distinguish name and serial number of encapsulated X509Certificate.
	 */
	private int dssId;

	/**
	 * The default algorithm used to compute the digest value of this certificate
	 */
	private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;

	/**
	 * Base 64 encoded digest value of this certificate computed for a given digest algorithm.
	 */
	private Map<DigestAlgorithm, String> digests;

	/**
	 * OCSP or CRL revocation data for this token.
	 */
	private RevocationToken revocationToken;

	/**
	 * Indicates if the certificate is self-signed. This attribute stays null till the first call to
	 * {@link #isSelfSigned()} function.
	 */
	private Boolean selfSigned;

	/**
	 * Extra information collected during the validation process.
	 */
	protected CertificateTokenValidationExtraInfo extraInfo;

	/**
	 * Normalized X500Principal (BMPString, TeletextString...)
	 */
	private X500Principal subjectX500PrincipalNormalized = null;

	/**
	 * This variable represents the {@code List} of certificate policies as {@code String}
	 */
	private List<String> policyIdentifiers = null;

	/**
	 * In the case of the XML signature this is the Id associated with the certificate if any.
	 */
	private String xmlId;

	/**
	 * This method returns an instance of {@link eu.europa.ec.markt.dss.validation102853.CertificateToken}.
	 *
	 * @param cert <code>X509Certificate</code>
	 * @param id   DSS unique certificate identifier
	 * @return
	 */
	static CertificateToken newInstance(final X509Certificate cert, final int id) {

		return new CertificateToken(cert, id);
	}

	/**
	 * Creates a CertificateToken wrapping the provided X509Certificate. A certificate must come from a source like:
	 * trusted store, trusted list, signature...
	 *
	 * @param x509Certificate X509Certificate
	 * @param id              DSS internal id (unique certificate's identifier)
	 */
	// TODO-Bob (29/07/2015):  null check should be performed of x509Certificate
	protected CertificateToken(final X509Certificate x509Certificate, final int id) {

		this.dssId = id;
		this.x509Certificate = x509Certificate;
		this.issuerX500Principal = DSSUtils.getIssuerX500Principal(x509Certificate);
		// The Algorithm OID is used and not the name {@code x509Certificate.getSigAlgName()}
		final String sigAlgOID = x509Certificate.getSigAlgOID();
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(sigAlgOID);
		this.algorithmUsedToSignToken = signatureAlgorithm;

		super.extraInfo = this.extraInfo = new CertificateTokenValidationExtraInfo();
	}

	/**
	 * This method adds the source type of the certificate (what is its origin). Each source is present only once.
	 *
	 * @param certSourceType
	 */
	public void addSourceType(final CertificateSourceType certSourceType) {

		if (certSourceType != null) {

			synchronized (sources) {
				if (!sources.contains(certSourceType)) {
					sources.add(certSourceType);
				}
			}
		}
	}

	/**
	 * This method adds the associated trusted service information.
	 *
	 * @param serviceInfo
	 */
	public void addServiceInfo(final ServiceInfo serviceInfo) {

		if (serviceInfo != null) {

			synchronized (associatedTSPS) {
				if (!associatedTSPS.contains(serviceInfo)) {
					associatedTSPS.add(serviceInfo);
				}
			}
		}
	}

	/**
	 * Returns a DSS unique certificate token identifier based on the issuer distinguish name and serial number.
	 */
	public int getDSSId() {

		return dssId;
	}

	/**
	 * Returns a string representation of the unique DSS certificate token identifier.
	 */
	public String getDSSIdAsString() {

		if (dssId == 0) {

			return "[" + x509Certificate.getSubjectX500Principal().getName(X500Principal.CANONICAL) + "]";
		}
		return "[" + dssId + "]";
	}

	@Override
	public String getAbbreviation() {

		return getDSSIdAsString();
	}

	/**
	 * @param revocationToken {code RevocationToken} to be associated with this {@code CertificateToken}
	 */
	public void setRevocationToken(final RevocationToken revocationToken) {

		this.revocationToken = revocationToken;
	}

	/**
	 * Returns the certificate revocation revocationToken object.
	 */
	public RevocationToken getRevocationToken() {

		return revocationToken;
	}

	/**
	 * Returns the public key associated with the certificate.<br>
	 * <p/>
	 * To get the encryption algorithm used with this public key call getAlgorithm() method.<br>
	 * RFC 2459:<br>
	 * 4.1.2.7 Subject Public Key Info
	 * <p/>
	 * This field is used to carry the public key and identify the algorithm with which the key is used. The algorithm is
	 * identified using the AlgorithmIdentifier structure specified in section 4.1.1.2. The object identifiers for the
	 * supported algorithms and the methods for encoding the public key materials (public key and parameters) are
	 * specified in section 7.3.
	 *
	 * @return
	 */
	public PublicKey getPublicKey() {

		return x509Certificate.getPublicKey();
	}

	/**
	 * Returns .
	 *
	 * @return
	 */
	public Date getNotAfter() {

		return x509Certificate.getNotAfter();
	}

	/**
	 * Returns .
	 *
	 * @return
	 */
	public Date getNotBefore() {

		return x509Certificate.getNotBefore();
	}

	/**
	 * Checks if the certificate is expired on the given date.
	 *
	 * @param date {@code Date} against which the check is performed
	 * @return {@code true} if the certificate is expired at the given date, {@code false} otherwise
	 * @throws DSSNullException If the {@code date} is {@code null} then {@code DSSNullException} is raised
	 */
	public boolean isExpiredOn(final Date date) throws DSSNullException {

		if (x509Certificate == null || date == null) {
			throw new DSSNullException(Date.class);
		}
		return x509Certificate.getNotAfter().before(date);
	}

	/**
	 * Checks if the certificate is not yet valid on the given date.
	 *
	 * @param date {@code Date} against which the check is performed
	 * @return {@code true} if the certificate is not yet valid at the given date, {@code false} otherwise
	 * @throws DSSNullException If the {@code date} is {@code null} then {@code DSSNullException} is raised
	 */
	public boolean isNotYetValidOn(final Date date) throws DSSNullException {

		if (x509Certificate == null || date == null) {
			throw new DSSNullException(Date.class);
		}
		return x509Certificate.getNotBefore().after(date);
	}

	/**
	 * Checks if the given date is in the validity period of the certificate.
	 *
	 * @param date
	 * @return
	 */
	public boolean isValidOn(final Date date) {

		if (x509Certificate == null || date == null) {
			return false;
		}
		try {
			x509Certificate.checkValidity(date);
			return true;
		} catch (CertificateExpiredException e) {
			return false;
		} catch (CertificateNotYetValidException e) {
			return false;
		}
	}

	/**
	 * This method indicates if the encapsulated certificate is revoked. In the case of a trusted certificate {@code false} is always returned.
	 *
	 * @return {@code null} if the revocation data cannot be checked, or {@code true} or {@code false}
	 */
	public Boolean isRevoked() {

		if (isTrusted()) {
			return false;
		}
		if (revocationToken == null) {
			return null;
		}
		final Boolean status = revocationToken.getStatus();
		if (status == null) {
			return null;
		}
		return !status;
	}

	/**
	 * Checks if the certificate is provided by the trusted source.
	 *
	 * @return {@code true} if the certificate is a part of a trusted list or trusted store
	 */
	public boolean isTrusted() {

		return sources.contains(CertificateSourceType.TRUSTED_LIST) || sources.contains(CertificateSourceType.TRUSTED_STORE);
	}

	/**
	 * Checks if the certificate is self-signed. Note that the signature is not checked. The result is only based on the comparison of the subject name and issuer name.
	 *
	 * @return {@code true} if the certificate is self-signed
	 */
	public boolean isSelfSigned() {

		if (selfSigned == null) {

			final String n1 = x509Certificate.getSubjectX500Principal().getName(X500Principal.CANONICAL);
			final String n2 = x509Certificate.getIssuerX500Principal().getName(X500Principal.CANONICAL);
			selfSigned = n1.equals(n2);
		}
		return selfSigned;
	}

	/**
	 * Gets the enclosed X509 Certificate.
	 *
	 * @return
	 */
	public X509Certificate getCertificate() {

		return x509Certificate;
	}

	/**
	 * Returns the encoded form of this certificate. X.509 certificates would be encoded as ASN.1 DER.
	 *
	 * @return the encoded form of this certificate
	 */
	@Override
	public byte[] getEncoded() {

		final byte[] bytes = DSSUtils.getEncoded(x509Certificate);
		return bytes;
	}

	/**
	 * Gets information about the context in which this certificate token was created (TRUSTED_LIST, TRUSTED_STORE, ...).
	 * This method does not guarantee that the token is trusted or not.
	 *
	 * @return
	 */
	public List<CertificateSourceType> getSources() {

		return Collections.unmodifiableList(sources);
	}

	/**
	 * Gets information about the trusted context of the certificate. See {@link eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo} for more information.
	 *
	 * @return
	 */
	public List<ServiceInfo> getAssociatedTSPS() {

		if (isTrusted()) {
			return Collections.unmodifiableList(associatedTSPS);
		}
		return null;
	}

	/**
	 * Gets the serialNumber value from the encapsulated certificate. The serial number is an integer assigned by the
	 * certification authority to each certificate. It must be unique for each certificate issued by a given CA.
	 *
	 * @return
	 */
	public BigInteger getSerialNumber() {

		return x509Certificate.getSerialNumber();
	}

	/**
	 * Returns the subject (subject distinguished name) value from the certificate as an X500Principal. If the subject
	 * value is empty, then the getName() method of the returned X500Principal object returns an empty string ("").
	 *
	 * @return
	 */
	public X500Principal getSubjectX500Principal() {

		if (subjectX500PrincipalNormalized == null) {
			subjectX500PrincipalNormalized = DSSUtils.getSubjectX500Principal(x509Certificate);
		}
		return subjectX500PrincipalNormalized;
	}

	@Override
	public boolean isSignedBy(final CertificateToken issuerToken) {

		signatureValid = false;
		signatureInvalidityReason = "";
		try {

			final PublicKey publicKey = issuerToken.getCertificate().getPublicKey();
			x509Certificate.verify(publicKey);
			signatureValid = true;
			if (!isSelfSigned()) {
				this.issuerToken = issuerToken;
			}
		} catch (InvalidKeyException e) {

			signatureInvalidityReason = "InvalidKeyException - on incorrect key.";
		} catch (CertificateException e) {

			signatureInvalidityReason = "CertificateException -  on encoding errors.";
		} catch (NoSuchAlgorithmException e) {

			signatureInvalidityReason = "NoSuchAlgorithmException - on unsupported signature algorithms.";
		} catch (SignatureException e) {

			signatureInvalidityReason = "SignatureException - on signature errors.";
			if (LOG.isDebugEnabled()) {
				LOG.debug("ERROR: {} is not signed by {}: {}", new Object[]{getAbbreviation(), issuerToken.getAbbreviation(), e.getMessage()});
			}
		} catch (NoSuchProviderException e) { // if there's no default provider.
			throw new DSSException(e);
		}
		return signatureValid;
	}

	/**
	 * Indicates that a X509Certificates corresponding private key is used by an authority to sign OCSP-Responses.<br>
	 * http://www.ietf.org/rfc/rfc3280.txt <br>
	 * http://tools.ietf.org/pdf/rfc6960.pdf 4.2.2.2<br>
	 * {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) keyPurpose(3)
	 * ocspSigning(9)}<br>
	 * OID: 1.3.6.1.5.5.7.3.9
	 *
	 * @return
	 */
	public boolean isOCSPSigning() {

		try {

			List<String> keyPurposes = x509Certificate.getExtendedKeyUsage();
			if (keyPurposes != null && keyPurposes.contains(OID.id_kp_OCSPSigning.getId())) {

				return true;
			}
		} catch (CertificateParsingException e) {

			LOG.warn(e.getMessage());
		}
		// Responder's certificate not valid for signing OCSP responses.
		return false;
	}

	/**
	 * Indicates if the revocation data should be checked for an OCSP signing certificate.<br>
	 * http://www.ietf.org/rfc/rfc2560.txt?number=2560<br>
	 * A CA may specify that an OCSP client can trust a responder for the lifetime of the responder's certificate. The CA
	 * does so by including the extension id-pkix-ocsp-nocheck. This SHOULD be a non-critical extension. The value of the
	 * extension should be NULL.
	 *
	 * @return
	 */
	public boolean hasIdPkixOcspNoCheckExtension() {

		final byte[] extensionValue = x509Certificate.getExtensionValue(OID.id_pkix_ocsp_no_check.getId());
		if (extensionValue != null) {

			try {

				final ASN1Primitive derObject = DSSASN1Utils.toASN1Primitive(extensionValue);
				if (derObject instanceof DEROctetString) {

					final boolean derOctetStringNull = DSSASN1Utils.isDEROctetStringNull((DEROctetString) derObject);
					return derOctetStringNull;
				}
			} catch (Exception e) {
				LOG.debug("Exception when processing 'id_pkix_ocsp_no_check'", e);
			}
		}
		return false;
	}

	/**
	 * Indicates if this certificate has an CRL extension expiredCertOnCRL.
	 *
	 * @return
	 */
	public boolean hasExpiredCertOnCRLExtension() {

		final byte[] extensionValue = x509Certificate.getExtensionValue(OID.id_ce_expiredCertsOnCRL.getId());
		if (extensionValue != null) {

			try {

				final ASN1Primitive derObject = DSSASN1Utils.toASN1Primitive(extensionValue);
				if (derObject instanceof DEROctetString) {

					final boolean derOctetStringNull = DSSASN1Utils.isDEROctetStringNull((DEROctetString) derObject);
					return derOctetStringNull;
				}
			} catch (Exception e) {
				LOG.debug("Exception when processing 'id_ce_expiredCertsOnCRL'", e);
			}
		}
		return false;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * Returns the encoded base 64 digest value of the certificate for a given algorithm. Can return null if the
	 * algorithm is unknown.
	 *
	 * @param digestAlgorithm
	 * @return
	 */
	public String getDigestValue(final DigestAlgorithm digestAlgorithm) {

		if (digests == null) {
			digests = new HashMap<DigestAlgorithm, String>();
		}
		String encodedDigest = digests.get(digestAlgorithm);
		if (encodedDigest == null) {

			final byte[] digest = DSSUtils.digest(digestAlgorithm, DSSUtils.getEncoded(x509Certificate));
			encodedDigest = DSSUtils.base64Encode(digest);
			digests.put(digestAlgorithm, encodedDigest);
		}
		return encodedDigest;
	}

	/**
	 * If it is the self-signed certificate then {@code this} is returned.
	 *
	 * @return the trust anchor associated with the certificate or {@code null} otherwise
	 */
	public CertificateToken getTrustAnchor() {

		if (isSelfSigned() && isTrusted()) {
			return this;
		}
		CertificateToken issuerCertToken = getIssuerToken();
		while (issuerCertToken != null) {
			if (issuerCertToken.isTrusted()) {
				return issuerCertToken;
			}
			issuerCertToken = issuerCertToken.getIssuerToken();
		}
		return null;
	}

	/**
	 * @return array of {@code byte}s representing the value of the CRL distribution point(s) extension of the wrapped certificate or {@code null} if it is not present.
	 */
	public byte[] getCRLDistributionPoints() {

		final String id = Extension.cRLDistributionPoints.getId();
		final byte[] extensionValue = x509Certificate.getExtensionValue(id);
		return extensionValue;
	}

	/**
	 * @return true if the wrapped certificate has cRLSign key usage bit set
	 */
	public boolean hasCRLSignKeyUsage() {

		final boolean[] keyUsage = x509Certificate.getKeyUsage();
		final boolean crlSignKeyUsage = keyUsage != null || (keyUsage != null && keyUsage[6]);
		return crlSignKeyUsage;
	}

	/**
	 * @return the size of the public key of the certificate
	 */
	public int getPublicKeyLength() {

		final int publicKeySize = DSSPKUtils.getPublicKeySize(getPublicKey());
		return publicKeySize;
	}

	/**
	 * This method checks if the certificate contains the given key usage bit.
	 *
	 * @param index the index of the key usage to be checked.
	 * @return true if contains
	 */
	public boolean checkKeyUsage(final int index) {
		return x509Certificate.getKeyUsage()[index];
	}

	/**
	 * Returns the object managing the validation extra info.
	 *
	 * @return
	 */
	public CertificateTokenValidationExtraInfo extraInfo() {

		return extraInfo;
	}

	/**
	 * Compares a given one-off id with this of the wrapped certificate.
	 *
	 * @param id The DSS validation process unique certificate's id
	 * @return
	 */
	public boolean equals(final int id) {

		return this.dssId == id;
	}

	@Override
	public int hashCode() {

		return dssId;
	}

	@Override
	public boolean equals(final Object obj) {

		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		return dssId == ((CertificateToken) obj).dssId;
	}

	@Override
	public String toString(String indentStr) {

		try {

			final StringBuffer out = new StringBuffer();
			out.append(indentStr).append("CertificateToken[\n");
			indentStr += "\t";

			String issuerAsString = "";
			if (issuerToken == null) {

				if (isSelfSigned()) {

					issuerAsString = "[SELF-SIGNED]";
				} else {
					issuerAsString = getIssuerX500Principal().toString();
				}
			} else {

				issuerAsString = issuerToken.getDSSIdAsString();
			}
			String certSource = "UNKNOWN";
			if (sources.size() > 0) {

				for (final CertificateSourceType source : sources) {

					final String name = source.name();
					if ("UNKNOWN".equals(certSource)) {

						certSource = name;
					} else {

						certSource += "/" + name;
					}
				}
			}
			out.append(indentStr).append(getDSSIdAsString()).append("<--").append(issuerAsString).append(", source=").append(certSource);
			out.append(", serial=" + x509Certificate.getSerialNumber()).append('\n');
			// Validity period
			final String certStartDate = DSSUtils.formatInternal(x509Certificate.getNotBefore());
			final String certEndDate = DSSUtils.formatInternal(x509Certificate.getNotAfter());
			out.append(indentStr).append("Validity period    : ").append(certStartDate).append(" - ").append(certEndDate).append('\n');
			out.append(indentStr).append("Subject name       : ").append(getSubjectX500Principal()).append('\n');
			out.append(indentStr).append("Issuer subject name: ").append(getIssuerX500Principal()).append('\n');
			if (sources.contains(CertificateSourceType.TRUSTED_LIST)) {

				for (ServiceInfo si : associatedTSPS) {

					out.append(indentStr).append("Service Info      :\n");
					indentStr += "\t";
					out.append(si.toString(indentStr));
					indentStr = indentStr.substring(1);
				}
			}
			out.append(indentStr).append("Signature algorithm: ").append(algorithmUsedToSignToken == null ? "?" : algorithmUsedToSignToken).append('\n');
			if (isTrusted()) {

				out.append(indentStr).append("Signature validity : Signature verification is not needed: trusted certificate\n");
			} else {

				if (signatureValid) {

					out.append(indentStr).append("Signature validity : VALID").append('\n');
				} else {

					if (!signatureInvalidityReason.isEmpty()) {

						out.append(indentStr).append("Signature validity : INVALID").append(" - ").append(signatureInvalidityReason).append('\n');
					}
				}
			}
			if (revocationToken != null) {

				out.append(indentStr).append("Revocation data[\n");
				indentStr += "\t";
				final CertificateToken revocationTokenIssuerToken = revocationToken.getIssuerToken();
				out.append(indentStr).append("Status: ").append(revocationToken.getStatus()).append(" / ").append(revocationToken.getIssuingTime())
					  .append(" / issuer's certificate ").append(revocationTokenIssuerToken != null ? revocationTokenIssuerToken.getDSSIdAsString() : "null").append('\n');
				indentStr = indentStr.substring(1);
				out.append(indentStr).append("]\n");
			} else {

				if (isSelfSigned()) {

					out.append(indentStr).append("Verification of revocation data is not necessary: self-signed certificate.\n");
				} else if (isTrusted()) {

					out.append(indentStr).append("Verification of revocation data is not necessary: trusted certificate.\n");
				} else {

					out.append(indentStr).append("There is no revocation data available!\n");
				}
			}
			if (issuerToken != null) {

				out.append(indentStr).append("Issuer certificate[\n");
				indentStr += "\t";
				if (issuerToken.isSelfSigned()) {

					out.append(indentStr).append(issuerToken.getDSSIdAsString()).append(" SELF-SIGNED");
				} else {

					out.append(issuerToken.toString(indentStr));
				}
				out.append('\n');
				indentStr = indentStr.substring(1);
				out.append(indentStr).append("]\n");
			}
			for (String info : this.extraInfo.getValidationInfo()) {

				out.append(indentStr).append("- ").append(info).append('\n');
			}
			indentStr = indentStr.substring(1);
			out.append(indentStr).append("]");
			return out.toString();
		} catch (Exception e) {

			return e.getMessage();
		}
	}

	/**
	 * This method returns the list of certificate policies of the encapsulated {@code X509Certificate}.<br>
	 * Extension "2.5.29.32"
	 *
	 * @return the {@code List} of certificate policies as {@code String}
	 */
	public List<String> getPolicyIdentifiers() {

		if (policyIdentifiers == null) {
			policyIdentifiers = DSSUtils.getPolicyIdentifiers(x509Certificate);
		}
		return policyIdentifiers;
	}

	private List<String> qcStatementsIdList = null;

	public List<String> getQCStatementsIdList() {

		if (qcStatementsIdList == null) {
			qcStatementsIdList = DSSUtils.getQCStatementsIdList(x509Certificate);
		}
		return qcStatementsIdList;
	}

	public boolean isQCP() {

		final List<String> policyIdentifiers = getPolicyIdentifiers();
		return policyIdentifiers.contains(OID.id_etsi_qcp_public.getId());
	}

	public boolean isQCPPlus() {

		final List<String> policyIdentifiers = getPolicyIdentifiers();
		return policyIdentifiers.contains(OID.id_etsi_qcp_public_with_sscd.getId());
	}

	public boolean isQCC() {

		final List<String> qcStatementsIdList = getQCStatementsIdList();
		return qcStatementsIdList.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId());
	}

	public boolean isQCSSCD() {

		final List<String> qcStatementsIdList = getQCStatementsIdList();
		return qcStatementsIdList.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId());
	}

	/**
	 * @return return the id associated with the certificate in case of an XML signature, or null
	 */
	public String getXmlId() {
		return xmlId;
	}

	/**
	 * Sets the Id associated with the certificate in case of an XML signature.
	 *
	 * @param xmlId id
	 */
	public void setXmlId(final String xmlId) {
		this.xmlId = xmlId;
	}

	/**
	 * This method returns a {@code String} representing the key usages of the certificate.
	 *
	 * @return {@code List} of {@code String}s of different certificate's key usages
	 */
	public List<String> getKeyUsageBits() {

		boolean[] keyUsageArray = x509Certificate.getKeyUsage();
		if (keyUsageArray == null) {
			return null;
		}
		final List<String> keyUsageBits = new ArrayList<String>();
		if (keyUsageArray[0]) {
			keyUsageBits.add(DIGITAL_SIGNATURE);
		}
		if (keyUsageArray[1]) {
			keyUsageBits.add(NON_REPUDIATION);
		}
		if (keyUsageArray[2]) {
			keyUsageBits.add(KEY_ENCIPHERMENT);
		}
		if (keyUsageArray[3]) {
			keyUsageBits.add(DATA_ENCIPHERMENT);
		}
		if (keyUsageArray[4]) {
			keyUsageBits.add(KEY_AGREEMENT);
		}
		if (keyUsageArray[5]) {
			keyUsageBits.add(KEY_CERT_SIGN);
		}
		if (keyUsageArray[6]) {
			keyUsageBits.add(CRL_SIGN);
		}
		if (keyUsageArray[7]) {
			keyUsageBits.add(ENCIPHER_ONLY);
		}
		if (keyUsageArray[8]) {
			keyUsageBits.add(DECIPHER_ONLY);
		}
		return keyUsageBits;
	}

	/**
	 * Gets the DER-encoded OCTET string for the extension value identified by the passed-in {@code oid}
	 * The {@code oid} string is represented by a set of non-negative positive integer numbers separated by periods.
	 *
	 * @param oid {@code ASN1ObjectIdentifier} value of the extension
	 * @return the DER-encoded octet string of the extension value or null if it is not present
	 */
	public byte[] getExtensionValue(final ASN1ObjectIdentifier oid) {

		final byte[] extensionValue = x509Certificate.getExtensionValue(oid.getId());
		return extensionValue;
	}
}
