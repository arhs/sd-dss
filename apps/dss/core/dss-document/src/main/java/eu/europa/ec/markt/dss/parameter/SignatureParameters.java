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

package eu.europa.ec.markt.dss.parameter;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.signature.BLevelParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

/**
 * Parameters for a Signature creation/extension
 *
 * @version $Revision: 2686 $ - $Date: 2013-10-02 14:02:33 +0200 (Wed, 02 Oct 2013) $
 */

public class SignatureParameters implements Serializable {

	/**
	 * This variable is used to ensure the uniqueness of the signature in the same document.
	 */
	protected static int signatureCounter = 0;
	ProfileParameters context;
	/**
	 * This parameter is used in one shot signature process. Cannot be used with 3-steps signature process.
	 */
	private SignatureTokenConnection signingToken;
	/**
	 * This parameter is used in one shot signature process. Cannot be used with 3-steps signature process.
	 */
	private DSSPrivateKeyEntry privateKeyEntry;
	/**
	 * This field contains the signing certificate.
	 */
	private X509Certificate signingCertificate;
	/**
	 * This variable indicates if it is possible to sign with an expired certificate.
	 */
	private boolean signWithExpiredCertificate = false;
	/**
	 * This field contains the {@code List} of chain of certificates. It includes the signing certificate.
	 */
	private List<ChainCertificate> certificateChain = new ArrayList<ChainCertificate>();
	private SignatureLevel signatureLevel;
	private SignaturePackaging signaturePackaging;

	/**
	 * XAdES: ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedInfo.
	 */
	private String signedInfoCanonicalizationMethod;

	/**
	 * XAdES: ds:CanonicalizationMethod indicates the canonicalization algorithm: Algorithm="..." for SignedProperties.
	 */
	private String signedPropertiesCanonicalizationMethod;

	/**
	 * XAdES: The ds:SignatureMethod indicates the algorithms used to sign ds:SignedInfo.
	 */
	private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	/**
	 * The encryption algorithm shall be automatically extracted from the signing token.
	 */
	private EncryptionAlgorithm encryptionAlgorithm = signatureAlgorithm.getEncryptionAlgorithm();

	/**
	 * XAdES: The digest algorithm used to hash ds:SignedInfo.
	 */
	private DigestAlgorithm digestAlgorithm = signatureAlgorithm.getDigestAlgorithm();

	/**
	 * XAdES: The digest algorithm used to hash ds:SignedInfo.
	 */
	private DigestAlgorithm signedPropertiesDigestAlgorithm = signatureAlgorithm.getDigestAlgorithm();

	private List<DSSReference> dssReferences;

	/**
	 * The object representing the parameters related to B- level.
	 */
	private BLevelParameters bLevelParams = new BLevelParameters();

	/**
	 * The object representing the parameters related to ASiC from of the signature.
	 */
	private ASiCParameters aSiCParams = new ASiCParameters();

	private String reason;
	private String contactInfo;
	private String deterministicId;

	private String toCounterSignSignatureId;
	private String xPathLocationString;

	private TimestampParameters signatureTimestampParameters;
	private TimestampParameters archiveTimestampParameters;
	private TimestampParameters contentTimestampParameters;

	private List<TimestampToken> contentTimestamps;

	private XPathQueryHolder toCountersignXPathQueryHolder = new XPathQueryHolder();
	private String toCounterSignSignatureValueId;
	/**
	 * The document to be signed
	 */
	private DSSDocument detachedContent;
	private eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder XPathQueryHolder;

	public SignatureParameters() {

	}

	// TODO-Bob (11/09/2014):  More then one document
	//	/**
	//	 * The documents to be signed. In the case where more then one document should be signed.
	//	 */
	//	private List<DSSDocument> detachedContents;

	/**
	 * Copy constructor (used by ASiC)
	 */
	public SignatureParameters(final SignatureParameters source) {

		if (source == null) {

			throw new DSSNullException(SignatureParameters.class);
		}
		bLevelParams = new BLevelParameters(source.bLevelParams);
		aSiCParams = new ASiCParameters(source.aSiCParams);
		certificateChain = new ArrayList<ChainCertificate>(source.certificateChain);
		contactInfo = source.contactInfo;
		deterministicId = source.getDeterministicId();
		digestAlgorithm = source.digestAlgorithm;
		encryptionAlgorithm = source.encryptionAlgorithm;
		detachedContent = source.detachedContent;
		privateKeyEntry = source.privateKeyEntry;
		reason = source.reason;
		signedPropertiesDigestAlgorithm = this.signedPropertiesDigestAlgorithm;
		signedInfoCanonicalizationMethod = source.signedInfoCanonicalizationMethod;
		signedPropertiesCanonicalizationMethod = source.signedPropertiesCanonicalizationMethod;
		signatureAlgorithm = source.signatureAlgorithm;
		signaturePackaging = source.signaturePackaging;
		signatureLevel = source.signatureLevel;
		signingToken = source.signingToken;
		signingCertificate = source.signingCertificate;
		signWithExpiredCertificate = source.signWithExpiredCertificate;
		contentTimestamps = source.contentTimestamps;
		toCounterSignSignatureId = source.getToCounterSignSignatureId();
		contentTimestampParameters = source.contentTimestampParameters;
		signatureTimestampParameters = source.signatureTimestampParameters;
		archiveTimestampParameters = source.archiveTimestampParameters;
		toCountersignXPathQueryHolder = source.toCountersignXPathQueryHolder;

		final List<DSSReference> references = source.getReferences();
		if (references != null && references.size() > 0) {

			dssReferences = new ArrayList<DSSReference>();
			for (final DSSReference reference : references) {

				final DSSReference dssReference = new DSSReference(reference);
				dssReferences.add(dssReference);
			}
		}
		// This is a simple copy of reference and not of the object content!
		context = source.context;
	}

	/**
	 * This method returns the Id of the signature to be countersigned.
	 *
	 * @return
	 */
	public String getToCounterSignSignatureId() {
		return toCounterSignSignatureId;
	}

	/**
	 * This method sets the Id of the signature to be countersigned.
	 *
	 * @param toCounterSignSignatureId
	 */
	public void setToCounterSignSignatureId(String toCounterSignSignatureId) {
		this.toCounterSignSignatureId = toCounterSignSignatureId;
	}

	/**
	 * This method returns the document to sign. In the case of the DETACHED signature this is the detached document.
	 *
	 * @return
	 * @deprecated (4.1.0) use {@code getContents}
	 */
	@Deprecated
	public DSSDocument getOriginalDocument() {
		return detachedContent;
	}

	/**
	 * When signing this method is internally invoked by the {@code AbstractSignatureService} and the related variable {@code detachedContent} is overwritten by the service
	 * parameter. In the case of the DETACHED signature this is the detached document. In the case of ASiC-S this is the document to be signed.<p />
	 * When extending this method must be invoked to indicate the {@code detachedContent}.
	 *
	 * @param document
	 * @deprecated (4.1.0) use {@code setContents}
	 */
	@Deprecated
	public void setOriginalDocument(final DSSDocument document) {
		this.detachedContent = document;
	}

	/**
	 * This method returns the document to sign. In the case of the DETACHED signature this is the detached document.
	 *
	 * @return
	 */
	public DSSDocument getDetachedContent() {
		return detachedContent;
	}

	/**
	 * When signing this method is internally invoked by the {@code AbstractSignatureService} and the related variable {@code detachedContent} is overwritten by the service
	 * parameter. In the case of the DETACHED signature this is the detached document. In the case of ASiC-S this is the document to be signed.<p />
	 * When extending this method must be invoked to indicate the {@code detachedContent}.
	 *
	 * @param detachedContent
	 */
	public void setDetachedContent(final DSSDocument detachedContent) {
		this.detachedContent = detachedContent;
	}

	/**
	 * Returns the list of the {@code TimestampToken} to be incorporated within the signature and representing the content-timestamp.
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	public List<TimestampToken> getContentTimestamps() {
		return contentTimestamps;
	}

	public void setContentTimestamps(final List<TimestampToken> contentTimestamps) {
		this.contentTimestamps = contentTimestamps;
	}

	public void addContentTimestamp(final TimestampToken contentTimestamp) {
		if (contentTimestamps == null) {
			contentTimestamps = new ArrayList<TimestampToken>();
		}
		this.contentTimestamps.add(contentTimestamp);
	}

	/**
	 * XAdES: The ID of xades:SignedProperties is contained in the signed content of the xades Signature. We must create this ID in a deterministic way.
	 *
	 * @return
	 */
	public String getDeterministicId() {

		if (deterministicId != null) {

			return deterministicId;
		}
		final int dssId = (signingCertificate == null ? 0 : CertificateIdentifier.getId(signingCertificate)) + signatureCounter++;
		deterministicId = DSSUtils.getDeterministicId(bLevelParams.getSigningDate(), dssId);
		return deterministicId;
	}

	/**
	 * This method allows to set the XAdES signature id. Be careful, if you change this id between the call to eu.europa.ec.markt.dss.signature.xades.XAdESService#toBeSigned(eu
	 * .europa.ec.markt.dss.signature.DSSDocument, eu.europa.ec.markt.dss.parameter.SignatureParameters) and eu.europa.ec.markt.dss.signature.xades.XAdESService#signDocument(eu
	 * .europa.ec.markt.dss.signature.DSSDocument, eu.europa.ec.markt.dss.parameter.SignatureParameters, byte[]) the created signature will be corrupted.
	 *
	 * @param deterministicId
	 */
	public void setDeterministicId(final String deterministicId) {

		this.deterministicId = deterministicId;
	}

	public ProfileParameters getContext() {
		if (context == null) {
			context = new ProfileParameters();
		}
		return context;
	}

	/**
	 * Get the signing certificate
	 *
	 * @return the value
	 */
	public X509Certificate getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * Set the signing certificate. If this certificate is not a part of the certificate chain then it's added as the first one of the chain.
	 *
	 * @param signingCertificate the value
	 */
	public void setSigningCertificate(final X509Certificate signingCertificate) {

		this.signingCertificate = signingCertificate;
		final ChainCertificate chainCertificate = new ChainCertificate(signingCertificate, true);
		if (!this.certificateChain.contains(chainCertificate)) {

			this.certificateChain.add(0, chainCertificate);
		}
	}

	/**
	 * Indicates if it is possible to sign with an expired certificate. The default value is false.
	 *
	 * @return
	 */
	public boolean isSignWithExpiredCertificate() {
		return signWithExpiredCertificate;
	}

	/**
	 * Allows to change the default behaviour regarding the use of an expired certificate.
	 *
	 * @param signWithExpiredCertificate
	 */
	public void setSignWithExpiredCertificate(final boolean signWithExpiredCertificate) {
		this.signWithExpiredCertificate = signWithExpiredCertificate;
	}

	/**
	 * Set the certificate chain
	 *
	 * @return the value
	 */
	public List<ChainCertificate> getCertificateChain() {
		return certificateChain;
	}

	/**
	 * This method sets the list of certificates which constitute the chain. If the certificate is already present in the array then it is ignored.
	 *
	 * @param certificateChainArray the array containing all certificates composing the chain
	 */
	public void setCertificateChain(final X509Certificate... certificateChainArray) {

		if (certificateChainArray == null || certificateChainArray.length == 0) {
			certificateChain.clear();
		}
		for (final X509Certificate certificate : certificateChainArray) {

			if (certificate != null) {

				final ChainCertificate chainCertificate = new ChainCertificate(certificate, false);
				if (!certificateChain.contains(chainCertificate)) {
					certificateChain.add(chainCertificate);
				}
			}
		}
	}

	/**
	 * Set the certificate chain
	 *
	 * @param certificateChain the {@code List} of {@code ChainCertificate}s
	 */
	public void setCertificateChain(final List<ChainCertificate> certificateChain) {

		if (certificateChain != null) {
			this.certificateChain = certificateChain;
		} else {
			this.certificateChain.clear();
		}
	}

	/**
	 * Clears the certificate chain
	 *
	 * @return the value
	 */
	public void clearCertificateChain() {
		certificateChain.clear();
	}

	/**
	 * Returns the private key entry
	 *
	 * @return the value
	 */
	public DSSPrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
	}

	/**
	 * This method sets the private key entry used to create the signature. Note that the certificate chain is reset, the encryption algorithm is set and the signature algorithm
	 * is updated.
	 * Note: The private key connot be extracted automatically from the {@code SignatureTokenConnection} because the latter can contain more then 01.
	 *
	 * @param privateKeyEntry {@code DSSPrivateKeyEntry} representing the private key entry to be used to sign
	 */
	public void setPrivateKeyEntry(final DSSPrivateKeyEntry privateKeyEntry) {

		this.privateKeyEntry = privateKeyEntry;
		// When the private key entry is set the certificate chain is reset
		certificateChain.clear();
		setSigningCertificate(privateKeyEntry.getCertificate());
		setCertificateChain(privateKeyEntry.getCertificateChain());
		final String encryptionAlgorithmName = this.signingCertificate.getPublicKey().getAlgorithm();
		this.encryptionAlgorithm = EncryptionAlgorithm.forName(encryptionAlgorithmName);
		this.signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
	}

	/**
	 * Returns the connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
	 *
	 * @return the value
	 */
	public SignatureTokenConnection getSigningToken() {
		return signingToken;
	}

	/**
	 * Sets the connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
	 *
	 * @param signingToken the value
	 */
	public void setSigningToken(final SignatureTokenConnection signingToken) {
		this.signingToken = signingToken;
	}

	/**
	 * Get signature format: XAdES_BES, XAdES_EPES, XAdES_BASELINE_T ../.. CAdES_BES...
	 *
	 * @return the value
	 */
	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	/**
	 * Set signature level. This field cannot be null.
	 *
	 * @param signatureLevel the value
	 */
	public void setSignatureLevel(final SignatureLevel signatureLevel) throws DSSNullException {

		if (signatureLevel == null) {
			throw new DSSNullException(SignatureLevel.class);
		}
		final SignatureForm signatureForm = signatureLevel.getSignatureForm();
		if (SignatureForm.ASiC_S.equals(signatureForm) || SignatureForm.ASiC_E.equals(signatureForm)) {

			aSiC().containerForm = signatureForm;
		}
		this.signatureLevel = signatureLevel;
	}

	/**
	 * Get Signature packaging
	 *
	 * @return the value
	 */
	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	/**
	 * Set Signature packaging
	 *
	 * @param signaturePackaging the value
	 */
	public void setSignaturePackaging(final SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}


	public DigestAlgorithm getSignedPropertiesDigestAlgorithm() {
		return signedPropertiesDigestAlgorithm;
	}

	public void setSignedPropertiesDigestAlgorithm(final DigestAlgorithm signedPropertiesDigestAlgorithm) {
		this.signedPropertiesDigestAlgorithm = signedPropertiesDigestAlgorithm;
	}

	/**
	 * @return (XAdES) the canonicalization algorithm to be used when dealing with SignedInfo.
	 */
	public String getSignedInfoCanonicalizationMethod() {
		return signedInfoCanonicalizationMethod;
	}

	/**
	 * Set the canonicalization algorithm to be used when dealing with SignedInfo (XAdES).
	 *
	 * @param signedInfoCanonicalizationMethod the canonicalization algorithm to be used when dealing with SignedInfo.
	 */
	public void setSignedInfoCanonicalizationMethod(final String signedInfoCanonicalizationMethod) {
		this.signedInfoCanonicalizationMethod = signedInfoCanonicalizationMethod;
	}

	/**
	 * @return (XAdES) the canonicalization algorithm to be used when dealing with SignedProperties.
	 */
	public String getSignedPropertiesCanonicalizationMethod() {
		return signedPropertiesCanonicalizationMethod;
	}

	/**
	 * Set the canonicalization algorithm to be used when dealing with SignedProperties (XAdES).
	 *
	 * @param signedPropertiesCanonicalizationMethod the canonicalization algorithm to be used when dealing with SignedInfo.
	 */
	public void setSignedPropertiesCanonicalizationMethod(final String signedPropertiesCanonicalizationMethod) {
		this.signedPropertiesCanonicalizationMethod = signedPropertiesCanonicalizationMethod;
	}

	/**
	 * @return the digest algorithm
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * @param digestAlgorithm the digest algorithm to set
	 */
	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {

		this.digestAlgorithm = digestAlgorithm;
		if (this.digestAlgorithm != null && this.encryptionAlgorithm != null) {

			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
		}
	}

	/**
	 * @return the encryption algorithm. It's determined by the privateKeyEntry and is null until the privateKeyEntry is set.
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	/**
	 * This setter should be used only when dealing with web services (or when signing in three steps). Usually the encryption algorithm is automatically extrapolated from the
	 * private key.
	 *
	 * @param encryptionAlgorithm
	 */
	public void setEncryptionAlgorithm(final EncryptionAlgorithm encryptionAlgorithm) {

		this.encryptionAlgorithm = encryptionAlgorithm;
		if (this.digestAlgorithm != null && this.encryptionAlgorithm != null) {

			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
		}
	}

	/**
	 * Gets the signature algorithm.
	 *
	 * @return the value
	 */
	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public List<DSSReference> getReferences() {

		return dssReferences;
	}

	public void setReferences(List<DSSReference> references) {
		this.dssReferences = references;
	}

	/**
	 * @return the reason (used by PAdES)
	 */
	public String getReason() {
		return reason;
	}

	/**
	 * @param reason the reason to set (used by PAdES)
	 */
	public void setReason(final String reason) {
		this.reason = reason;
	}

	/**
	 * @return the contactInfo (used by PAdES)
	 */
	public String getContactInfo() {
		return contactInfo;
	}

	/**
	 * @param contactInfo the contactInfo to set (used by PAdES)
	 */
	public void setContactInfo(final String contactInfo) {
		this.contactInfo = contactInfo;
	}

	public BLevelParameters bLevel() {

		return bLevelParams;
	}

	public ASiCParameters aSiC() {

		if (aSiCParams == null) {
			aSiCParams = new ASiCParameters();
		}
		return aSiCParams;
	}

	public TimestampParameters getSignatureTimestampParameters() {
		return signatureTimestampParameters;
	}

	public void setSignatureTimestampParameters(TimestampParameters signatureTimestampParameters) {
		this.signatureTimestampParameters = signatureTimestampParameters;
	}

	public TimestampParameters getArchiveTimestampParameters() {
		return archiveTimestampParameters;
	}

	public void setArchiveTimestampParameters(TimestampParameters archiveTimestampParameters) {
		this.archiveTimestampParameters = archiveTimestampParameters;
	}

	public TimestampParameters getContentTimestampParameters() {
		return contentTimestampParameters;
	}

	public void setContentTimestampParameters(TimestampParameters contentTimestampParameters) {
		this.contentTimestampParameters = contentTimestampParameters;
	}

	public String getXPathLocationString() {
		return xPathLocationString;
	}

	public void setXPathLocationString(String xPathLocationString) {
		this.xPathLocationString = xPathLocationString;
	}

	public XPathQueryHolder getXPathQueryHolder() {
		return XPathQueryHolder;
	}

	/**
	 * This method allows to set the {@code XPathQueryHolder} to be used when creating signatures.
	 *
	 * @param XPathQueryHolder {@code XPathQueryHolder} related to the signature schema to be used
	 */
	public void setXPathQueryHolder(XPathQueryHolder XPathQueryHolder) {
		this.XPathQueryHolder = XPathQueryHolder;
	}

	public XPathQueryHolder getToCountersignXPathQueryHolder() {
		return toCountersignXPathQueryHolder;
	}

	public void setToCountersignXPathQueryHolder(XPathQueryHolder toCountersignXPathQueryHolder) {
		this.toCountersignXPathQueryHolder = toCountersignXPathQueryHolder;
	}

	public String getToCounterSignSignatureValueId() {
		return toCounterSignSignatureValueId;
	}

	public void setToCounterSignSignatureValueId(String toCounterSignSignatureValueId) {
		this.toCounterSignSignatureValueId = toCounterSignSignatureValueId;
	}

	@Override
	public String toString() {
		return "SignatureParameters{" +
			  "signingToken=" + signingToken +
			  ", privateKeyEntry=" + privateKeyEntry +
			  ", signingCertificate=" + signingCertificate +
			  ", signWithExpiredCertificate=" + signWithExpiredCertificate +
			  ", certificateChain_=" + certificateChain +
			  ", context=" + context +
			  ", signatureLevel=" + signatureLevel +
			  ", signaturePackaging=" + signaturePackaging +
			  ", signatureAlgorithm=" + signatureAlgorithm +
			  ", encryptionAlgorithm=" + encryptionAlgorithm +
			  ", digestAlgorithm=" + digestAlgorithm +
			  ", references=" + dssReferences +
			  ", bLevelParams=" + bLevelParams +
			  ", aSiCParams=" + aSiCParams +
			  ", reason='" + reason + '\'' +
			  ", contactInfo='" + contactInfo + '\'' +
			  ", deterministicId='" + deterministicId + '\'' +
			  ", signatureTimestampParameters=" + signatureTimestampParameters +
			  ", archiveTimestampParameters=" + archiveTimestampParameters +
			  ", contentTimestamps=" + contentTimestamps +
			  ", detachedContent=" + detachedContent +
			  ", toCountersignSignatureId=" + toCounterSignSignatureId +
			  ", toCountersignXPathQueryHolder=" + toCountersignXPathQueryHolder +
			  '}';
	}
}
