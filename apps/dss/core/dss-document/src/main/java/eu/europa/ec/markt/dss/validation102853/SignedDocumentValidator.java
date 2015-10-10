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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSPKUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;
import eu.europa.ec.markt.dss.validation102853.bean.CandidatesForSigningCertificate;
import eu.europa.ec.markt.dss.validation102853.bean.CertificateValidity;
import eu.europa.ec.markt.dss.validation102853.bean.CertifiedRole;
import eu.europa.ec.markt.dss.validation102853.bean.CommitmentType;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.cades.CMSDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.crl.ListCRLSource;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.ObjectFactory;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlBasicSignatureType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertificate;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertificateChainType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertificatePolicies;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertifiedRolesType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlChainCertificate;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlClaimedRoles;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCommitmentTypeIndication;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlDetachedContents;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlDigestAlgAndValueType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlDistinguishedName;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlInfoType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlKeyUsageBits;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlMessage;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlPolicy;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlQCStatement;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlQualifiers;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlReference;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlReferencesType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlRevocationType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignature;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignatureScopeType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignatureScopes;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignedObjectsType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignedSignature;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSigningCertificateType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlStructuralValidationType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTimestampType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTimestamps;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlUsedCertificates;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.ocsp.ListOCSPSource;
import eu.europa.ec.markt.dss.validation102853.pades.PAdESSignature;
import eu.europa.ec.markt.dss.validation102853.pades.PDFDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.policy.Constraint;
import eu.europa.ec.markt.dss.validation102853.policy.EtsiValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScope;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinder;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XMLDocumentValidator;


/**
 * Validate the signed document. The content of the document is determined automatically. It can be: XML, CAdES(p7m), PDF or ASiC(zip).
 * <p/>
 * SignatureScopeFinder can be set using the appropriate setter (ex. setCadesSignatureScopeFinder). By default, this class will use the
 * default SignatureScopeFinder as defined by eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinderFactory
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
public abstract class SignedDocumentValidator implements DocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(SignedDocumentValidator.class);
	private static final byte[] xmlPreamble = new byte[]{'<', '?', 'x', 'm', 'l'};
	private static final byte[] xmlUtf8 = new byte[]{-17, -69, -65, '<', '?'};
	private static final byte[] pdfPreamble = new byte[]{'%', 'P', 'D', 'F', '-'};
	/*
	 * The factory used to create DiagnosticData
	 */
	protected static final ObjectFactory DIAGNOSTIC_DATA_OBJECT_FACTORY = new ObjectFactory();
	/**
	 * This variable can hold a specific {@code ProcessExecutor}
	 */
	protected ProcessExecutor processExecutor = null;
	protected SignatureScopeFinder<CAdESSignature> cadesSignatureScopeFinder = null;
	protected SignatureScopeFinder<PAdESSignature> padesSignatureScopeFinder = null;
	protected SignatureScopeFinder<XAdESSignature> xadesSignatureScopeFinder = null;
	/**
	 * This is the pool of certificates used in the validation process. The pools present in the certificate verifier are merged and added to this pool.
	 */
	protected CertificatePool validationCertPool;

	/**
	 * The document to validate (with the signature(s))
	 */
	protected DSSDocument document;

	/**
	 * - In case of a detached signature this {@code List} contains the signed documents.
	 * - In case of a signed manifest file this {@code List} contains the documents to be validated against the manifest file.
	 */
	protected List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();

	protected CertificateToken providedSigningCertificateToken = null;
	/**
	 * The reference to the certificate verifier. The current DSS implementation proposes {@link CryptographicSourceProvider}. This verifier
	 * encapsulates the references to different sources used in the signature validation process.
	 */
	protected CertificateVerifier certificateVerifier;
	/**
	 * This list contains the list of signatures
	 */
	protected List<AdvancedSignature> signatures = null;
	/**
	 * This variable contains the reference to the diagnostic data.
	 */
	protected DiagnosticData jaxbDiagnosticData; // JAXB object
	protected Map<String, Constraint> customConstraintMap;
	private ValidationPolicy countersignatureValidationPolicy;
	// Single policy document to use with all signatures.
	private File policyDocument;
	private HashMap<String, File> policyDocuments;

	/**
	 * This method guesses the document format and returns an appropriate document validator.
	 *
	 * @param dssDocument The instance of {@code DSSDocument} to validate
	 * @return returns the specific instance of SignedDocumentValidator in terms of the document type
	 */
	public static SignedDocumentValidator fromDocument(final DSSDocument dssDocument) {

		final String dssDocumentName = dssDocument.getName();
		if (dssDocumentName != null && MimeType.XML.equals(MimeType.fromFileName(dssDocumentName))) {

			return new XMLDocumentValidator(dssDocument);
		}

		int headerLength = 500;
		byte[] preamble = new byte[headerLength];
		int read = DSSUtils.readToArray(dssDocument, headerLength, preamble);
		if (read < 5) {

			throw new DSSException("The signature is not found.");
		}
		if (isXmlPreamble(preamble)) {

			return new XMLDocumentValidator(dssDocument);
		} else if (isPdfPreamble(preamble)) {

			// TODO (29/08/2014): DSS-356
			return new PDFDocumentValidator(dssDocument);
		} else if (preamble[0] == 'P' && preamble[1] == 'K') {

			return ASiCContainerValidator.getInstanceForAsics(dssDocument);
		} else if (preamble[0] == 0x30) {

			return new CMSDocumentValidator(dssDocument);
		} else {
			throw new DSSException("Document format not recognized/handled");
		}
	}

	private static boolean isXmlPreamble(byte[] preamble) {

		return DSSUtils.equals(preamble, xmlPreamble, 5) || DSSUtils.equals(preamble, xmlUtf8, 5);
	}

	private static boolean isPdfPreamble(byte[] preamble) {

		return DSSUtils.equals(preamble, pdfPreamble, 5);
	}

	@Override
	public DSSDocument getDocument() {

		return document;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {

		return detachedContents;
	}

	@Override
	public void setDetachedContents(final List<DSSDocument> detachedContents) {

		this.detachedContents = detachedContents;
	}

	@Override
	public void defineSigningCertificate(final X509Certificate x509Certificate) {

		if (x509Certificate == null) {
			throw new DSSNullException(X509Certificate.class);
		}
		if (validationCertPool == null) {
			throw new DSSNullException(CertificatePool.class, "validationCertPool");
		}
		providedSigningCertificateToken = validationCertPool.getInstance(x509Certificate, CertificateSourceType.OTHER);
	}

	/**
	 * To carry out the validation process of the signature(s) some external sources of certificates and of revocation data can be needed. The certificate verifier is used to pass
	 * these values. Note that once this setter is called any change in the content of the <code>CommonTrustedCertificateSource</code> or in adjunct certificate source is not
	 * taken into account.
	 *
	 * @param certificateVerifier
	 */
	@Override
	public void setCertificateVerifier(final CertificateVerifier certificateVerifier) {

		this.certificateVerifier = certificateVerifier;
		validationCertPool = certificateVerifier.createValidationPool();
	}

	/**
	 * This method allows to provide an external policy document to be used with all signatures within the document to validate.
	 *
	 * @param policyDocument
	 */
	@Override
	public void setPolicyFile(final File policyDocument) {

		this.policyDocument = policyDocument;
	}

	/**
	 * This method allows to provide an external policy document to be used with a given signature id.
	 *
	 * @param signatureId    signature id
	 * @param policyDocument
	 */
	@Override
	public void setPolicyFile(final String signatureId, final File policyDocument) {

		if (policyDocuments == null) {

			policyDocuments = new HashMap<String, File>();
		}
		policyDocuments.put(signatureId, policyDocument);
	}

	/**
	 * This setter allows to indicate the countersignature {@code ValidationPolicy} to be used.
	 *
	 * @param countersignatureValidationPolicy {@code ValidationPolicy} to be used
	 */
	public void setCountersignatureValidationPolicy(final ValidationPolicy countersignatureValidationPolicy) {
		this.countersignatureValidationPolicy = countersignatureValidationPolicy;
	}

	@Override
	public Reports validateDocument() {

		return validateDocument((InputStream) null);
	}

	@Override
	public Reports validateDocument(final URL validationPolicyURL) {

		if (validationPolicyURL == null) {
			return validateDocument((InputStream) null);
		}
		try {
			return validateDocument(validationPolicyURL.openStream());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public Reports validateDocument(final String policyResourcePath) {

		if (policyResourcePath == null) {
			return validateDocument((InputStream) null);
		}
		return validateDocument(getClass().getResourceAsStream(policyResourcePath));
	}

	@Override
	public Reports validateDocument(final File policyFile) {

		if (policyFile == null || !policyFile.exists()) {
			return validateDocument((InputStream) null);
		}
		final InputStream inputStream = DSSUtils.toByteArrayInputStream(policyFile);
		return validateDocument(inputStream);
	}

	/**
	 * Validates the document and all its signatures. The policyDataStream contains the constraint file. If null or empty the default file is used.
	 *
	 * @param policyDataStream {@code InputStream}
	 */
	@Override
	public Reports validateDocument(final InputStream policyDataStream) {

		final Document validationPolicyDom = ValidationResourceManager.loadPolicyData(policyDataStream);
		return validateDocument(validationPolicyDom);
	}

	/**
	 * Validates the document and all its signatures. The {@code validationPolicyDom} contains the constraint file. If null or empty the default file is used.
	 *
	 * @param validationPolicyDom {@code Document}
	 * @return
	 */
	@Override
	public Reports validateDocument(final Document validationPolicyDom) {

		final ValidationPolicy validationPolicy = new EtsiValidationPolicy(validationPolicyDom);
		return validateDocument(validationPolicy);
	}

	/**
	 * Validates the document and all its signatures. The {@code validationPolicyDom} contains the constraint file. If null or empty the default file is used.
	 *
	 * @param validationPolicy {@code ValidationPolicy}
	 * @return
	 */
	@Override
	public Reports validateDocument(final ValidationPolicy validationPolicy) {

		LOG.info("Document validation...");
		if (certificateVerifier == null) {

			throw new DSSNullException(CertificateVerifier.class);
		}
		Date date1 = null;
		if (LOG.isInfoEnabled()) {
			date1 = new Date();
		}
		final ProcessExecutor executor = provideProcessExecutorInstance();
		validationPolicy.setCustomConstraintMap(customConstraintMap);
		executor.setValidationPolicy(validationPolicy);
		if (countersignatureValidationPolicy == null) {

			final Document countersignaturePolicyData = ValidationResourceManager.loadCountersignaturePolicyData(null);
			countersignatureValidationPolicy = new EtsiValidationPolicy(countersignaturePolicyData);
		}
		executor.setCountersignatureValidationPolicy(countersignatureValidationPolicy);

		final DiagnosticData jaxbDiagnosticData = generateDiagnosticData();

		final Document diagnosticDataDom = ValidationResourceManager.convert(jaxbDiagnosticData);
		executor.setDiagnosticDataDom(diagnosticDataDom);
		Date date2 = null;
		if (LOG.isTraceEnabled()) {

			date2 = new Date();
			final long dateDiff = DSSUtils.getDateDiff(date1, date2, TimeUnit.MILLISECONDS);
			LOG.trace("diff 1: " + dateDiff + " ms.");
		}
		final Reports reports = executor.execute();
		if (LOG.isTraceEnabled()) {

			Date date3 = new Date();
			final long dateDiff = DSSUtils.getDateDiff(date2, date3, TimeUnit.MILLISECONDS);
			LOG.trace("diff 2: " + dateDiff + " ms.");
		}
		return reports;
	}

	@Override
	public void setProcessExecutor(final ProcessExecutor processExecutor) {

		this.processExecutor = processExecutor;
	}

	/**
	 * This method returns the process executor. If the instance of this class is not yet instantiated then the new instance is created.
	 *
	 * @return {@code ProcessExecutor}
	 */
	public ProcessExecutor provideProcessExecutorInstance() {

		if (processExecutor == null) {
			processExecutor = new CustomProcessExecutor();
		}
		return processExecutor;
	}

	/**
	 * This method generates the diagnostic data. This is the set of all data extracted from the signature, associated certificates and trusted lists. The diagnostic data contains
	 * also the results of basic computations (hash check, signature integrity, certificates chain...
	 */
	private DiagnosticData generateDiagnosticData() {

		prepareDiagnosticData();

		final List<AdvancedSignature> allSignatureList = getAllSignatures();

		final ListCRLSource signatureCRLSource = getSignatureCrlSource(allSignatureList);
		certificateVerifier.setSignatureCRLSource(signatureCRLSource);

		final ListOCSPSource signatureOCSPSource = getSignatureOcspSource(allSignatureList);
		certificateVerifier.setSignatureOCSPSource(signatureOCSPSource);

		final ValidationContext validationContext = new SignatureValidationContext(certificateVerifier, validationCertPool);
		final ProcessExecutor processExecutor = provideProcessExecutorInstance();
		final int concurrentThreadNumber = processExecutor.getConcurrentThreadNumber();
		if (concurrentThreadNumber > 0) {

			final ExecutorService executorService = Executors.newFixedThreadPool(concurrentThreadNumber);
			validationContext.setExecutorService(executorService);
		}

		// The list of all signing certificates is created to allow a parallel validation.
		prepareCertificatesAndTimestamps(allSignatureList, validationContext);

		validationContext.setCurrentTime(processExecutor.getCurrentTime());
		validationContext.validate();

		// For each signature present in the document to be validated the extraction of diagnostic data is launched.
		final Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();
		for (final AdvancedSignature signature : allSignatureList) {

			final XmlSignature xmlSignature = validateSignature(signature);
			usedCertificatesDigestAlgorithms.addAll(signature.getUsedCertificatesDigestAlgorithms());
			jaxbDiagnosticData.getSignature().add(xmlSignature);
		}
		final Set<CertificateToken> processedCertificates = validationContext.getProcessedCertificates();
		dealUsedCertificates(usedCertificatesDigestAlgorithms, processedCertificates);

		return jaxbDiagnosticData;
	}

	/**
	 * This method prepares the {@code DiagnosticData} object to store all static information about the signatures being validated.
	 */
	private void prepareDiagnosticData() {

		jaxbDiagnosticData = DIAGNOSTIC_DATA_OBJECT_FACTORY.createDiagnosticData();

		// To cope with tests it can be interesting to always keep the same file name within the reports (without the path).
		String absolutePath = document.getAbsolutePath();
		if (CertificateIdentifier.isUniqueIdentifier()) {

			absolutePath = document.getName();
		}
		jaxbDiagnosticData.setDocumentName(absolutePath);

		if (detachedContents.size() > 0) {

			final XmlDetachedContents xmlDetachedContents = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlDetachedContents();
			final List<String> documentNameList = xmlDetachedContents.getDocumentName();
			for (final DSSDocument detachedContent : this.detachedContents) {

				documentNameList.add(detachedContent.getAbsolutePath());
			}
			jaxbDiagnosticData.setDetachedContents(xmlDetachedContents);
		}
	}

	/**
	 * This method returns the list of all signatures including the countersignatures to be validated.
	 *
	 * @return {@code List} of {@code AdvancedSignature} to validate
	 */
	private List<AdvancedSignature> getAllSignatures() {

		final List<AdvancedSignature> allSignatureList = new ArrayList<AdvancedSignature>();
		for (final AdvancedSignature signature : getSignatures()) {

			allSignatureList.add(signature);
			final List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
			allSignatureList.addAll(counterSignatures);
		}
		return allSignatureList;
	}

	/**
	 * For all signatures to be validated this method merges the OCSP sources.
	 *
	 * @param allSignatureList {@code List} of {@code AdvancedSignature}s to validate including the countersignatures
	 * @return {@code ListCRLSource}
	 */
	private ListCRLSource getSignatureCrlSource(final List<AdvancedSignature> allSignatureList) {

		final ListCRLSource signatureCrlSource = new ListCRLSource();
		for (final AdvancedSignature signature : allSignatureList) {

			signatureCrlSource.addAll(signature.getCRLSource());
		}
		return signatureCrlSource;
	}

	/**
	 * For all signatures to be validated this method merges the OCSP sources.
	 *
	 * @param allSignatureList {@code List} of {@code AdvancedSignature}s to validate including the countersignatures
	 * @return {@code ListOCSPSource}
	 */
	private ListOCSPSource getSignatureOcspSource(final List<AdvancedSignature> allSignatureList) {

		final ListOCSPSource signatureOcspSource = new ListOCSPSource();
		for (final AdvancedSignature signature : allSignatureList) {

			signatureOcspSource.addAll(signature.getOCSPSource());
		}
		return signatureOcspSource;
	}

	/**
	 * @param allSignatureList  {@code List} of {@code AdvancedSignature}s to validate including the countersignatures
	 * @param validationContext {@code ValidationContext} is the implementation of the validators for: certificates, timestamps and revocation data.
	 */
	private void prepareCertificatesAndTimestamps(final List<AdvancedSignature> allSignatureList, final ValidationContext validationContext) {

		for (final AdvancedSignature signature : allSignatureList) {

			final List<CertificateToken> candidates = signature.getCertificateSource().getCertificates();
			for (final CertificateToken certificateToken : candidates) {
				validationContext.addCertificateTokenForVerification(certificateToken);
			}
			final List<TimestampToken> timestampTokenList = signature.prepareTimestamps();
			for (final TimestampToken timestampToken : timestampTokenList) {
				validationContext.addTimestampTokenForVerification(timestampToken);
			}
		}
	}

	/**
	 * Main method for validating a signature. The diagnostic data is extracted.
	 *
	 * @param signature Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @return The JAXB object containing all diagnostic data pertaining to the signature
	 */
	private XmlSignature validateSignature(final AdvancedSignature signature) throws DSSException {

		final XmlSignature xmlSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignature();
		try {

			final CertificateToken signingToken = dealWithSignature(signature, xmlSignature);

			dealWithPolicy(signature, xmlSignature);

			dealWithCertificateChain(xmlSignature, signingToken);

			signature.validateTimestamps();

			XmlTimestamps xmlTimestamps = null;
			xmlTimestamps = dealWithTimestamps(xmlTimestamps, signature.getContentTimestamps());

			xmlTimestamps = dealWithTimestamps(xmlTimestamps, signature.getSignatureTimestamps());

			xmlTimestamps = dealWithTimestamps(xmlTimestamps, signature.getTimestampsX1());

			xmlTimestamps = dealWithTimestamps(xmlTimestamps, signature.getTimestampsX2());

			xmlTimestamps = dealWithTimestamps(xmlTimestamps, signature.getArchiveTimestamps());

			xmlSignature.setTimestamps(xmlTimestamps);
		} catch (Exception e) {

			// Any raised error is just logged and the process continues with the next signature.
			LOG.warn(e.getMessage(), e);
			addErrorMessage(xmlSignature, e);
		}
		return xmlSignature;
	}

	private void addErrorMessage(final XmlSignature xmlSignature, final Exception e) {

		addErrorMessage(xmlSignature, e.toString());
	}

	private void addErrorMessage(final XmlSignature xmlSignature, final String message) {

		String currentMessage = message;
		String errorMessage = xmlSignature.getErrorMessage();
		if (DSSUtils.isBlank(errorMessage)) {

			errorMessage = currentMessage;
		} else {

			errorMessage += "<br />" + currentMessage;
		}
		xmlSignature.setErrorMessage(errorMessage);
	}

	/**
	 * @param xmlTimestamps
	 * @param timestampTokens
	 */
	private XmlTimestamps dealWithTimestamps(XmlTimestamps xmlTimestamps, final List<TimestampToken> timestampTokens) {

		if (!timestampTokens.isEmpty()) {

			for (final TimestampToken timestampToken : timestampTokens) {

				final XmlTimestampType xmlTimestampToken = xmlForTimestamp(timestampToken);
				if (xmlTimestamps == null) {

					xmlTimestamps = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTimestamps();
				}
				xmlTimestamps.getTimestamp().add(xmlTimestampToken);
			}
		}
		return xmlTimestamps;
	}

	/**
	 * @param timestampToken
	 * @return
	 */
	private XmlTimestampType xmlForTimestamp(final TimestampToken timestampToken) {

		final XmlTimestampType xmlTimestampToken = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTimestampType();
		xmlTimestampToken.setId(timestampToken.getDSSId());
		final TimestampType timestampType = timestampToken.getTimeStampType();
		xmlTimestampToken.setType(timestampType.name());
		xmlTimestampToken.setProductionTime(DSSXMLUtils.createXMLGregorianCalendar(timestampToken.getGenerationTime()));

		xmlTimestampToken.setSignedDataDigestAlgo(timestampToken.getSignedDataDigestAlgo().getName());
		xmlTimestampToken.setEncodedSignedDataDigestValue(timestampToken.getEncodedSignedDataDigestValue());
		xmlTimestampToken.setMessageImprintDataFound(timestampToken.isMessageImprintDataFound());
		xmlTimestampToken.setMessageImprintDataIntact(timestampToken.isMessageImprintDataIntact());
		xmlTimestampToken.setCanonicalizationMethod(timestampToken.getCanonicalizationMethod());

		final SignatureAlgorithm signatureAlgorithm = timestampToken.getSignatureAlgorithm();
		final XmlBasicSignatureType xmlBasicSignatureType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();
		if (signatureAlgorithm != null) {

			xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgorithm().getName());
			xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgorithm().getName());
		}
		final String keyLength = timestampToken.getKeyLength();
		xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);

		final boolean signatureValid = timestampToken.isSignatureValid();
		xmlBasicSignatureType.setReferenceDataFound(signatureValid /*timestampToken.isReferenceDataFound()*/);
		xmlBasicSignatureType.setReferenceDataIntact(signatureValid /*timestampToken.isReferenceDataIntact()*/);
		xmlBasicSignatureType.setSignatureIntact(signatureValid /*timestampToken.isSignatureIntact()*/);
		xmlBasicSignatureType.setSignatureValid(signatureValid);
		xmlTimestampToken.setBasicSignature(xmlBasicSignatureType);

		final CertificateToken issuerToken = timestampToken.getIssuerToken();

		XmlSigningCertificateType xmlTSSignCert = xmlForSigningCertificate(issuerToken);
		xmlTimestampToken.setSigningCertificate(xmlTSSignCert);

		final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(issuerToken);
		xmlTimestampToken.setCertificateChain(xmlCertChainType);

		final List<TimestampReference> timestampReferences = timestampToken.getTimestampedReferences();
		if (timestampReferences != null && !timestampReferences.isEmpty()) {

			final XmlSignedObjectsType xmlSignedObjectsType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignedObjectsType();
			final List<XmlDigestAlgAndValueType> xmlDigestAlgAndValueList = xmlSignedObjectsType.getDigestAlgAndValue();

			for (final TimestampReference timestampReference : timestampReferences) {

				final TimestampReferenceCategory timestampedCategory = timestampReference.getCategory();
				if (TimestampReferenceCategory.SIGNATURE.equals(timestampedCategory)) {

					final XmlSignedSignature xmlSignedSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignedSignature();
					xmlSignedSignature.setId(timestampReference.getSignatureId());
					xmlSignedObjectsType.getSignedSignature().add(xmlSignedSignature);
				} else {

					final XmlDigestAlgAndValueType xmlDigestAlgAndValue = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlDigestAlgAndValueType();
					xmlDigestAlgAndValue.setDigestMethod(timestampReference.getDigestAlgorithm());
					xmlDigestAlgAndValue.setDigestValue(timestampReference.getDigestValue());
					xmlDigestAlgAndValue.setCategory(timestampedCategory.name());
					xmlDigestAlgAndValueList.add(xmlDigestAlgAndValue);
				}
			}
			xmlTimestampToken.setSignedObjects(xmlSignedObjectsType);
		}
		return xmlTimestampToken;
	}

	/**
	 * @param issuerToken
	 * @return
	 */
	private XmlCertificateChainType xmlForCertificateChain(final CertificateToken issuerToken) {

		if (issuerToken != null) {

			CertificateToken issuerToken_ = issuerToken;
			final XmlCertificateChainType xmlCertChainType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertificateChainType();
			final List<XmlChainCertificate> certChainTokens = xmlCertChainType.getChainCertificate();
			do {

				final XmlChainCertificate xmlCertToken = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlChainCertificate();
				xmlCertToken.setId(issuerToken_.getDSSId());
				final CertificateSourceType mainSource = getCertificateMainSourceType(issuerToken_);
				xmlCertToken.setSource(mainSource.name());
				certChainTokens.add(xmlCertToken);
				if (issuerToken_.isTrusted() || issuerToken_.isSelfSigned()) {

					break;
				}
				issuerToken_ = issuerToken_.getIssuerToken();
			} while (issuerToken_ != null);
			return xmlCertChainType;
		}
		return null;
	}

	private CertificateSourceType getCertificateMainSourceType(final CertificateToken issuerToken) {

		CertificateSourceType mainSource = CertificateSourceType.UNKNOWN;
		final List<CertificateSourceType> sourceList = issuerToken.getSources();
		if (sourceList.size() > 0) {

			if (sourceList.contains(CertificateSourceType.TRUSTED_LIST)) {

				mainSource = CertificateSourceType.TRUSTED_LIST;
			} else if (sourceList.contains(CertificateSourceType.TRUSTED_STORE)) {

				mainSource = CertificateSourceType.TRUSTED_STORE;
			} else {
				mainSource = sourceList.get(0);
			}
		}
		return mainSource;
	}

	/**
	 * @param usedCertificatesDigestAlgorithms
	 * @param usedCertTokens
	 */
	private void dealUsedCertificates(final Set<DigestAlgorithm> usedCertificatesDigestAlgorithms, final Set<CertificateToken> usedCertTokens) {

		final XmlUsedCertificates xmlUsedCerts = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlUsedCertificates();
		jaxbDiagnosticData.setUsedCertificates(xmlUsedCerts);
		for (final CertificateToken certToken : usedCertTokens) {

			final XmlCertificate xmlCert = dealCertificateDetails(usedCertificatesDigestAlgorithms, certToken);
			dealQCStatement(certToken, xmlCert);
			dealTrustedService(certToken, xmlCert);
			dealRevocationData(certToken, xmlCert);
			dealCertificateValidationInfo(certToken, xmlCert);
			xmlUsedCerts.getCertificate().add(xmlCert);
			if (LOG.isTraceEnabled()) {

				LOG.trace("PEM for certificate: " + certToken.getAbbreviation() + "--->");
				final String pem = DSSUtils.convertToPEM(certToken.getCertificate());
				LOG.trace("\n" + pem);
			}
		}
	}

	/**
	 * This method deals with the Qualified Certificate Statements. The retrieved information is transformed to the JAXB object.<br>
	 * Qualified Certificate Statements, the following Policies are checked:<br>
	 * - Qualified Certificates Policy "0.4.0.1456.1.1” (QCP);<br>
	 * - Qualified Certificates Policy "0.4.0.1456.1.2" (QCP+);<br>
	 * - Qualified Certificates Compliance "0.4.0.1862.1.1";<br>
	 * - Qualified Certificates SCCD "0.4.0.1862.1.4";<br>
	 *
	 * @param certToken
	 * @param xmlCert
	 */
	private void dealQCStatement(final CertificateToken certToken, final XmlCertificate xmlCert) {

		if (!certToken.isTrusted()) {

			/// System.out.println("--> QCStatement for: " + certToken.getAbbreviation());
			final XmlQCStatement xmlQCS = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlQCStatement();
			xmlQCS.setQCP(certToken.isQCP());
			xmlQCS.setQCPPlus(certToken.isQCPPlus());
			xmlQCS.setQCC(certToken.isQCC());
			xmlQCS.setQCSSCD(certToken.isQCSSCD());
			xmlCert.setQCStatement(xmlQCS);
		}
	}

	/**
	 * This method deals with the certificate validation extra information. The retrieved information is transformed to the JAXB object.
	 *
	 * @param certToken
	 * @param xmlCert
	 */
	private void dealCertificateValidationInfo(final CertificateToken certToken, final XmlCertificate xmlCert) {

		final List<String> list = certToken.getValidationInfo();
		if (list.size() > 0) {

			final XmlInfoType xmlInfo = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlInfoType();
			for (String message : list) {

				final XmlMessage xmlMessage = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlMessage();
				xmlMessage.setId(0);
				xmlMessage.setValue(message);
				xmlInfo.getMessage().add(xmlMessage);
			}
			xmlCert.setInfo(xmlInfo);
		}
	}

	/**
	 * This method deals with the certificate's details. The retrieved information is transformed to the JAXB object.
	 *
	 * @param usedDigestAlgorithms set of different digest algorithms used to compute certificate digest
	 * @param certToken            current certificate token
	 * @return
	 */
	private XmlCertificate dealCertificateDetails(final Set<DigestAlgorithm> usedDigestAlgorithms, final CertificateToken certToken) {

		final XmlCertificate xmlCert = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertificate();

		xmlCert.setId(certToken.getDSSId());

		XmlDistinguishedName xmlDistinguishedName = xmlForDistinguishedName(X500Principal.CANONICAL, certToken.getSubjectX500Principal());
		xmlCert.getSubjectDistinguishedName().add(xmlDistinguishedName);
		xmlDistinguishedName = xmlForDistinguishedName(X500Principal.RFC2253, certToken.getSubjectX500Principal());
		xmlCert.getSubjectDistinguishedName().add(xmlDistinguishedName);

		xmlDistinguishedName = xmlForDistinguishedName(X500Principal.CANONICAL, certToken.getIssuerX500Principal());
		xmlCert.getIssuerDistinguishedName().add(xmlDistinguishedName);
		xmlDistinguishedName = xmlForDistinguishedName(X500Principal.RFC2253, certToken.getIssuerX500Principal());
		xmlCert.getIssuerDistinguishedName().add(xmlDistinguishedName);

		xmlCert.setSerialNumber(certToken.getSerialNumber());

		for (final DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {

			final XmlDigestAlgAndValueType xmlDigestAlgAndValue = new XmlDigestAlgAndValueType();
			xmlDigestAlgAndValue.setDigestMethod(digestAlgorithm.getName());
			xmlDigestAlgAndValue.setDigestValue(certToken.getDigestValue(digestAlgorithm));
			xmlCert.getDigestAlgAndValue().add(xmlDigestAlgAndValue);
		}
		xmlCert.setIssuerCertificate(certToken.getIssuerTokenDSSId());
		xmlCert.setNotAfter(DSSXMLUtils.createXMLGregorianCalendar(certToken.getNotAfter()));
		xmlCert.setNotBefore(DSSXMLUtils.createXMLGregorianCalendar(certToken.getNotBefore()));
		final PublicKey publicKey = certToken.getPublicKey();
		xmlCert.setPublicKeySize(DSSPKUtils.getPublicKeySize(publicKey));
		xmlCert.setPublicKeyEncryptionAlgo(DSSPKUtils.getPublicKeyEncryptionAlgo(publicKey));

		xmlForKeyUsageBits(certToken, xmlCert);

		xmlForCertificatePolicies(certToken, xmlCert);

		if (certToken.isOCSPSigning()) {

			xmlCert.setIdKpOCSPSigning(true);
		}
		if (certToken.hasIdPkixOcspNoCheckExtension()) {

			xmlCert.setIdPkixOcspNoCheck(true);
		}
		if (certToken.hasExpiredCertOnCRLExtension()) {

			xmlCert.setExpiredCertOnCRL(true);
		}

		final XmlBasicSignatureType xmlBasicSignatureType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();

		final SignatureAlgorithm signatureAlgorithm = certToken.getSignatureAlgorithm();
		xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgorithm().getName());
		xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgorithm().getName());
		final String keyLength = certToken.getKeyLength();
		xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);
		final boolean signatureIntact = certToken.isSignatureValid();
		xmlBasicSignatureType.setReferenceDataFound(signatureIntact);
		xmlBasicSignatureType.setReferenceDataIntact(signatureIntact);
		xmlBasicSignatureType.setSignatureIntact(signatureIntact);
		xmlBasicSignatureType.setSignatureValid(signatureIntact);
		xmlCert.setBasicSignature(xmlBasicSignatureType);

		final CertificateToken issuerToken = certToken.getIssuerToken();
		final XmlSigningCertificateType xmlSigningCertificate = xmlForSigningCertificate(issuerToken);
		xmlCert.setSigningCertificate(xmlSigningCertificate);

		final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(issuerToken);
		xmlCert.setCertificateChain(xmlCertChainType);

		xmlCert.setSelfSigned(certToken.isSelfSigned());
		xmlCert.setTrusted(certToken.isTrusted());

		return xmlCert;
	}

	private void xmlForKeyUsageBits(final CertificateToken certToken, final XmlCertificate xmlCert) {

		final List<String> keyUsageBits = certToken.getKeyUsageBits();
		if (DSSUtils.isEmpty(keyUsageBits)) {
			return;
		}
		final XmlKeyUsageBits xmlKeyUsageBits = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlKeyUsageBits();
		final List<String> xmlKeyUsageBitItems = xmlKeyUsageBits.getKeyUsage();
		for (final String keyUsageBit : keyUsageBits) {
			xmlKeyUsageBitItems.add(keyUsageBit);
		}
		xmlCert.setKeyUsageBits(xmlKeyUsageBits);
	}

	private void xmlForCertificatePolicies(final CertificateToken certToken, final XmlCertificate xmlCert) {

		final List<String> certTokenPolicyIdentifiers = certToken.getPolicyIdentifiers();
		if (DSSUtils.isEmpty(certTokenPolicyIdentifiers)) {
			return;
		}
		final XmlCertificatePolicies xmlCertificatePolicies = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertificatePolicies();
		final List<String> xmlCertificatePolicyItems = xmlCertificatePolicies.getCertificatePolicy();
		for (final String certificatePolicy : certTokenPolicyIdentifiers) {
			xmlCertificatePolicyItems.add(certificatePolicy);
		}
		xmlCert.setCertificatePolicies(xmlCertificatePolicies);
	}

	private XmlDistinguishedName xmlForDistinguishedName(final String x500PrincipalFormat, final X500Principal X500PrincipalName) {

		final XmlDistinguishedName xmlDistinguishedName = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlDistinguishedName();
		xmlDistinguishedName.setFormat(x500PrincipalFormat);
		final String x500PrincipalName = X500PrincipalName.getName(x500PrincipalFormat);
		xmlDistinguishedName.setValue(x500PrincipalName);
		return xmlDistinguishedName;
	}

	/**
	 * This method deals with the certificate chain. The retrieved information is transformed to the JAXB object.
	 *
	 * @param xmlSignature The JAXB object containing all diagnostic data pertaining to the signature
	 * @param signingToken {@code CertificateToken} relative to the current signature
	 */
	private void dealWithCertificateChain(final XmlSignature xmlSignature, final CertificateToken signingToken) {

		if (signingToken != null) {

			final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(signingToken);
			xmlSignature.setCertificateChain(xmlCertChainType);
		}
	}

	/**
	 * This method deals with the trusted service information in case of trusted certificate. The retrieved information is transformed to the JAXB object.
	 *
	 * @param certToken
	 * @param xmlCert
	 */
	private void dealTrustedService(final CertificateToken certToken, final XmlCertificate xmlCert) {

		if (certToken.isTrusted()) {

			return;
		}
		final CertificateToken trustAnchor = certToken.getTrustAnchor();
		if (trustAnchor == null) {

			return;
		}
		final List<ServiceInfo> serviceInfoList = trustAnchor.getAssociatedTSPS();
		if (serviceInfoList == null) {

			return;
		}
		for (final ServiceInfo serviceInfo : serviceInfoList) {

			//			System.out.println("---------------------------------------------");
			//			System.out.println(serviceInfo);

			final XmlTrustedServiceProviderType xmlTSP = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTrustedServiceProviderType();
			xmlTSP.setTSPName(serviceInfo.getTspName());
			xmlTSP.setTSPServiceName(serviceInfo.getServiceName());
			xmlTSP.setTSPServiceType(serviceInfo.getType());
			xmlTSP.setWellSigned(serviceInfo.isTlWellSigned());

			final Date statusStartDate = serviceInfo.getStatusStartDate();
			xmlTSP.setStatus(serviceInfo.getStatus());
			xmlTSP.setStartDate(DSSXMLUtils.createXMLGregorianCalendar(statusStartDate));
			xmlTSP.setEndDate(DSSXMLUtils.createXMLGregorianCalendar(serviceInfo.getStatusEndDate()));
			xmlTSP.setExpiredCertsRevocationInfo(DSSXMLUtils.createXMLGregorianCalendar(serviceInfo.getExpiredCertsRevocationInfo()));

			// Check of the associated conditions to identify the qualifiers
			final List<String> qualifiers = serviceInfo.getQualifiers(certToken);
			if (!qualifiers.isEmpty()) {

				final XmlQualifiers xmlQualifiers = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlQualifiers();
				for (String qualifier : qualifiers) {

					xmlQualifiers.getQualifier().add(qualifier);
				}
				xmlTSP.setQualifiers(xmlQualifiers);
			}
			xmlCert.getTrustedServiceProvider().add(xmlTSP);
			//			}
		}
	}

	/**
	 * This method deals with the revocation data of a certificate. The retrieved information is transformed to the JAXB object.
	 *
	 * @param certToken
	 * @param xmlCert
	 */
	private void dealRevocationData(final CertificateToken certToken, final XmlCertificate xmlCert) {

		final XmlRevocationType xmlRevocation = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlRevocationType();
		final RevocationToken revocationToken = certToken.getRevocationToken();
		if (revocationToken != null) {

			final Boolean revocationTokenStatus = revocationToken.getStatus();
			// revocationTokenStatus can be null when OCSP return Unknown. In this case we set status to false.
			xmlRevocation.setStatus(revocationTokenStatus == null ? false : revocationTokenStatus);
			xmlRevocation.setDateTime(DSSXMLUtils.createXMLGregorianCalendar(revocationToken.getRevocationDate()));
			xmlRevocation.setReason(revocationToken.getReason());
			xmlRevocation.setIssuingTime(DSSXMLUtils.createXMLGregorianCalendar(revocationToken.getIssuingTime()));
			xmlRevocation.setNextUpdate(DSSXMLUtils.createXMLGregorianCalendar(revocationToken.getNextUpdate()));
			xmlRevocation.setSource(revocationToken.getClass().getSimpleName());
			xmlRevocation.setSourceAddress(revocationToken.getSourceURL());

			final XmlBasicSignatureType xmlBasicSignatureType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();
			final SignatureAlgorithm revocationSignatureAlgo = revocationToken.getSignatureAlgorithm();
			final boolean unknownAlgorithm = revocationSignatureAlgo == null;
			final String encryptionAlgorithmName = unknownAlgorithm ? "?" : revocationSignatureAlgo.getEncryptionAlgorithm().getName();
			xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(encryptionAlgorithmName);
			final String keyLength = revocationToken.getKeyLength();
			xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);

			final String digestAlgorithmName = unknownAlgorithm ? "?" : revocationSignatureAlgo.getDigestAlgorithm().getName();
			xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(digestAlgorithmName);
			final boolean signatureValid = revocationToken.isSignatureValid();
			xmlBasicSignatureType.setReferenceDataFound(signatureValid);
			xmlBasicSignatureType.setReferenceDataIntact(signatureValid);
			xmlBasicSignatureType.setSignatureIntact(signatureValid);
			xmlBasicSignatureType.setSignatureValid(signatureValid);
			xmlRevocation.setBasicSignature(xmlBasicSignatureType);

			final CertificateToken issuerToken = revocationToken.getIssuerToken();
			final XmlSigningCertificateType xmlRevocationSignCert = xmlForSigningCertificate(issuerToken);
			xmlRevocation.setSigningCertificate(xmlRevocationSignCert);

			final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(issuerToken);
			xmlRevocation.setCertificateChain(xmlCertChainType);

			final List<String> list = revocationToken.getValidationInfo();
			if (list.size() > 0) {

				final XmlInfoType xmlInfo = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlInfoType();
				for (String message : list) {

					final XmlMessage xmlMessage = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlMessage();
					xmlMessage.setId(0);
					xmlMessage.setValue(message);
					xmlInfo.getMessage().add(xmlMessage);
				}
				xmlRevocation.setInfo(xmlInfo);
			}
			xmlCert.setRevocation(xmlRevocation);
		}
	}

	/**
	 * This method deals with the signature policy. The retrieved information is transformed to the JAXB object.
	 *
	 * @param signature    Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @param xmlSignature The JAXB object containing all diagnostic data pertaining to the signature
	 */
	private void dealWithPolicy(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		SignaturePolicy signaturePolicy = null;
		try {

			signaturePolicy = signature.getPolicyId();
		} catch (Exception e) {

			final String msg = "Error when extracting the signature policy: " + e.getMessage();
			LOG.warn(msg, e);
			addErrorMessage(xmlSignature, msg);
		}
		if (signaturePolicy == null) {

			return;
		}

		final XmlPolicy xmlPolicy = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlPolicy();
		xmlSignature.setPolicy(xmlPolicy);

		final String policyId = signaturePolicy.getIdentifier();
		xmlPolicy.setId(policyId);

		final String policyUrl = signaturePolicy.getUrl();
		xmlPolicy.setUrl(policyUrl);

		final String notice = signaturePolicy.getNotice();
		xmlPolicy.setNotice(notice);

		/**
		 * ETSI 102 853:
		 * 3) Obtain the digest of the resulting document against which the digest value present in the property/attribute will be checked:
		 */
		if (policyDocument == null && (policyUrl == null || policyUrl.isEmpty())) {

			xmlPolicy.setIdentified(false);
			if (policyId.isEmpty()) {

				xmlPolicy.setStatus(true);
			} else {

				xmlPolicy.setStatus(false);
			}
			return;
		}
		xmlPolicy.setIdentified(true);

		byte[] policyBytes = null;
		try {

			if (policyDocument == null) {

				final DataLoader dataLoader = certificateVerifier.getDataLoader();
				policyBytes = dataLoader.get(policyUrl);
			} else {

				policyBytes = DSSUtils.toByteArray(policyDocument);
			}
		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			xmlPolicy.setStatus(false);
			xmlPolicy.setProcessingError(e.toString());
			//Do nothing
			LOG.warn(e.toString());
			return;
		}

		DigestAlgorithm signPolicyHashAlgFromPolicy = null;
		String policyDigestHexValueFromPolicy = null;
		String recalculatedDigestHexValue = null;
		/**
		 * a)
		 * If the resulting document is based on TR 102 272 [i.2] (ESI: ASN.1 format for signature policies), use the digest value present in the
		 * SignPolicyDigest element from the resulting document. Check that the digest algorithm indicated
		 * in the SignPolicyDigestAlg from the resulting document is equal to the digest algorithm indicated in the property.
		 * // TODO: (Bob: 2013 Dec 10) ETSI to be notified: it is signPolicyHashAlg and not SignPolicyDigestAlg
		 */
		try {

			final ASN1Sequence asn1Sequence = DSSASN1Utils.toASN1Primitive(policyBytes);
			final ASN1Sequence signPolicyHashAlgObject = (ASN1Sequence) asn1Sequence.getObjectAt(0);
			final AlgorithmIdentifier signPolicyHashAlgIdentifier = AlgorithmIdentifier.getInstance(signPolicyHashAlgObject);
			final String signPolicyHashAlgOID = signPolicyHashAlgIdentifier.getAlgorithm().getId();
			signPolicyHashAlgFromPolicy = DigestAlgorithm.forOID(signPolicyHashAlgOID);

			final ASN1Sequence signPolicyInfo = (ASN1Sequence) asn1Sequence.getObjectAt(1);
			//signPolicyInfo.getObjectAt(1);

			final ASN1OctetString signPolicyHash = (ASN1OctetString) asn1Sequence.getObjectAt(2);
			final byte[] policyDigestValueFromPolicy = signPolicyHash.getOctets();
			policyDigestHexValueFromPolicy = DSSUtils.toHex(policyDigestValueFromPolicy);

			final byte[] hashAlgorithmDEREncoded = DSSASN1Utils.getEncoded(signPolicyHashAlgIdentifier);
			final byte[] signPolicyInfoDEREncoded = DSSASN1Utils.getEncoded(signPolicyInfo);
			final byte[] recalculatedDigestValue = DSSUtils.digest(signPolicyHashAlgFromPolicy, hashAlgorithmDEREncoded, signPolicyInfoDEREncoded);
			recalculatedDigestHexValue = DSSUtils.toHex(recalculatedDigestValue);

			/**
			 * b)
			 * If the resulting document is based on TR 102 038 [i.3] ((ESI) XML format for signature policies), use the digest value present in
			 * signPolicyHash element from the resulting document. Check that the digest
			 * algorithm indicated in the signPolicyHashAlg from the resulting document is equal to the digest algorithm indicated in the attribute.
			 */

			/**
			 * c)
			 * In all other cases, compute the digest using the digesting algorithm indicated in the children of the property/attribute.
			 */

			String policyDigestValueFromSignature = signaturePolicy.getDigestValue();
			policyDigestValueFromSignature = policyDigestValueFromSignature.toUpperCase();

			/**
			 * The use of a zero-sigPolicyHash value is to ensure backwards compatibility with earlier versions of the
			 * current document. If sigPolicyHash is zero, then the hash value should not be checked against the
			 * calculated hash value of the signature policy.
			 */

			final DigestAlgorithm signPolicyHashAlgFromSignature = signaturePolicy.getDigestAlgorithm();
			if (!signPolicyHashAlgFromPolicy.equals(signPolicyHashAlgFromSignature)) {

				xmlPolicy.setProcessingError(
					  "The digest algorithm indicated in the SignPolicyHashAlg from the resulting document (" + signPolicyHashAlgFromPolicy + ") is not equal to the digest " +
							"algorithm (" + signPolicyHashAlgFromSignature + ").");
				xmlPolicy.setDigestAlgorithmsEqual(false);
				xmlPolicy.setStatus(false);
				return;
			}
			xmlPolicy.setDigestAlgorithmsEqual(true);

			boolean equal = policyDigestValueFromSignature.equals(recalculatedDigestHexValue);
			xmlPolicy.setStatus(equal);
			if (!equal) {

				xmlPolicy.setProcessingError(
					  "The policy digest value (" + policyDigestValueFromSignature + ") does not match the re-calculated digest value (" + recalculatedDigestHexValue + ").");
				return;
			}
			equal = policyDigestValueFromSignature.equals(policyDigestHexValueFromPolicy);
			xmlPolicy.setStatus(equal);
			if (!equal) {

				xmlPolicy.setProcessingError(
					  "The policy digest value (" + policyDigestValueFromSignature + ") does not match the digest value from the policy file (" + policyDigestHexValueFromPolicy + ").");
			}
		} catch (RuntimeException e) {
			// When any error (communication) we just set the status to false
			xmlPolicy.setStatus(false);
			xmlPolicy.setProcessingError(e.toString());
			//Do nothing
			LOG.warn(e.toString());
		}
	}

	/**
	 * This method deals with the basic signature data. The retrieved information is transformed to the JAXB object. The signing certificate token is returned if found.
	 *
	 * @param signature    Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @param xmlSignature The JAXB object containing all diagnostic data pertaining to the signature
	 * @return
	 */
	private CertificateToken dealWithSignature(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		checkIfCountersignature(signature, xmlSignature);
		performStructuralValidation(signature, xmlSignature);
		performSignatureCryptographicValidation(signature, xmlSignature);
		xmlSignature.setId(signature.getId());
		xmlSignature.setDateTime(DSSXMLUtils.createXMLGregorianCalendar(signature.getSigningTime()));
		final SignatureLevel dataFoundUpToLevel = signature.getDataFoundUpToLevel();
		final String value = dataFoundUpToLevel == null ? "UNKNOWN" : dataFoundUpToLevel.name();
		xmlSignature.setSignatureFormat(value);

		dealWithSignatureProductionPlace(signature, xmlSignature);

		dealWithCommitmentTypeIndication(signature, xmlSignature);

		dealWithClaimedRole(signature, xmlSignature);

		final String contentType = signature.getContentType();
		xmlSignature.setContentType(contentType);

		final String contentIdentifier = signature.getContentIdentifier();
		xmlSignature.setContentIdentifier(contentIdentifier);

		final String contentHints = signature.getContentHints();
		xmlSignature.setContentHints(contentHints);

		dealWithCertifiedRole(signature, xmlSignature);

		final CertificateValidity certificateValidity = dealSigningCertificate(signature, xmlSignature);

		final XmlBasicSignatureType xmlBasicSignature = getXmlBasicSignatureType(xmlSignature);
		final EncryptionAlgorithm encryptionAlgorithm = signature.getEncryptionAlgorithm();
		final String encryptionAlgorithmString = encryptionAlgorithm == null ? "?" : encryptionAlgorithm.getName();
		xmlBasicSignature.setEncryptionAlgoUsedToSignThisToken(encryptionAlgorithmString);
		// signingCertificateValidity can be null in case of a non AdES signature.
		final CertificateToken signingCertificateToken = certificateValidity == null ? null : certificateValidity.getCertificateToken();
		final int keyLength = signingCertificateToken == null ? 0 : signingCertificateToken.getPublicKeyLength();
		xmlBasicSignature.setKeyLengthUsedToSignThisToken(String.valueOf(keyLength));
		final DigestAlgorithm digestAlgorithm = signature.getDigestAlgorithm();
		final String digestAlgorithmString = digestAlgorithm == null ? "?" : digestAlgorithm.getName();
		xmlBasicSignature.setDigestAlgoUsedToSignThisToken(digestAlgorithmString);
		xmlSignature.setBasicSignature(xmlBasicSignature);
		dealSignatureScope(xmlSignature, signature);

		return signingCertificateToken;
	}

	private void checkIfCountersignature(AdvancedSignature signature, XmlSignature xmlSignature) {

		final AdvancedSignature masterSignature = signature.getMasterSignature();
		if (masterSignature != null) {

			xmlSignature.setType(AttributeValue.COUNTERSIGNATURE);
			xmlSignature.setParentId(masterSignature.getId());
		}
	}

	private void performStructuralValidation(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		final ValidationPolicy validationPolicy = provideProcessExecutorInstance().getValidationPolicy();
		if (validationPolicy == null) {
			return;
		}
		final Constraint structuralValidationConstraint = validationPolicy.getStructuralValidationConstraint();
		if (structuralValidationConstraint == null || Constraint.Level.IGNORE.equals(structuralValidationConstraint.getLevel())) {
			return;
		}
		final String structureValid = signature.validateStructure();
		if (structureValid != null) {

			final XmlStructuralValidationType xmlStructuralValidationType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlStructuralValidationType();
			xmlStructuralValidationType.setValid(DSSUtils.EMPTY.equals(structureValid));
			if (!DSSUtils.EMPTY.equals(structureValid)) {
				xmlStructuralValidationType.setMessage(structureValid);
			}
			xmlSignature.setStructuralValidation(xmlStructuralValidationType);
		}
	}

	private void dealWithSignatureProductionPlace(AdvancedSignature signature, XmlSignature xmlSignature) {
		final SignatureProductionPlace signatureProductionPlace = signature.getSignatureProductionPlace();
		if (signatureProductionPlace != null) {

			final XmlSignatureProductionPlace xmlSignatureProductionPlace = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignatureProductionPlace();
			xmlSignatureProductionPlace.setCountryName(signatureProductionPlace.getCountryName());
			xmlSignatureProductionPlace.setStateOrProvince(signatureProductionPlace.getStateOrProvince());
			xmlSignatureProductionPlace.setPostalCode(signatureProductionPlace.getPostalCode());
			xmlSignatureProductionPlace.setAddress(signatureProductionPlace.getAddress());
			xmlSignatureProductionPlace.setCity(signatureProductionPlace.getCity());
			xmlSignature.setSignatureProductionPlace(xmlSignatureProductionPlace);
		}
	}

	private void dealWithCertifiedRole(AdvancedSignature signature, XmlSignature xmlSignature) {
		List<CertifiedRole> certifiedRoles = null;
		try {
			certifiedRoles = signature.getCertifiedSignerRoles();
		} catch (DSSException e) {

			LOG.warn("Exception", e);
			addErrorMessage(xmlSignature, e);
		}
		if (certifiedRoles != null && !certifiedRoles.isEmpty()) {

			for (final CertifiedRole certifiedRole : certifiedRoles) {

				final XmlCertifiedRolesType xmlCertifiedRolesType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertifiedRolesType();

				xmlCertifiedRolesType.setCertifiedRole(certifiedRole.getRole());
				xmlCertifiedRolesType.setNotBefore(DSSXMLUtils.createXMLGregorianCalendar(certifiedRole.getNotBefore()));
				xmlCertifiedRolesType.setNotAfter(DSSXMLUtils.createXMLGregorianCalendar(certifiedRole.getNotAfter()));
				xmlSignature.getCertifiedRoles().add(xmlCertifiedRolesType);
			}
		}
	}

	private void dealWithClaimedRole(AdvancedSignature signature, XmlSignature xmlSignature) {
		String[] claimedRoles = null;
		try {
			claimedRoles = signature.getClaimedSignerRoles();
		} catch (DSSException e) {

			LOG.warn("Exception: ", e);
			addErrorMessage(xmlSignature, e);
		}
		if (claimedRoles != null && claimedRoles.length > 0) {

			final XmlClaimedRoles xmlClaimedRoles = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlClaimedRoles();
			for (final String claimedRole : claimedRoles) {

				xmlClaimedRoles.getClaimedRole().add(claimedRole);
			}
			xmlSignature.setClaimedRoles(xmlClaimedRoles);
		}
	}

	private void dealWithCommitmentTypeIndication(AdvancedSignature signature, XmlSignature xmlSignature) {

		CommitmentType commitmentTypeIndication = null;
		try {
			commitmentTypeIndication = signature.getCommitmentTypeIndication();
		} catch (Exception e) {

			LOG.warn("Exception: ", e);
			addErrorMessage(xmlSignature, e);
		}
		if (commitmentTypeIndication != null) {

			final XmlCommitmentTypeIndication xmlCommitmentTypeIndication = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCommitmentTypeIndication();
			final List<String> xmlIdentifiers = xmlCommitmentTypeIndication.getIdentifier();

			final List<String> identifiers = commitmentTypeIndication.getIdentifiers();
			for (final String identifier : identifiers) {

				xmlIdentifiers.add(identifier);
			}
			xmlSignature.setCommitmentTypeIndication(xmlCommitmentTypeIndication);
		}
	}

	protected void dealSignatureScope(XmlSignature xmlSignature, AdvancedSignature signature) {
		final XmlSignatureScopes xmlSignatureScopes = new XmlSignatureScopes();
		final List<SignatureScope> signatureScope = getSignatureScopeFinder().findSignatureScope(signature);
		for (final SignatureScope scope : signatureScope) {
			final XmlSignatureScopeType xmlSignatureScope = new XmlSignatureScopeType();
			xmlSignatureScope.setName(scope.getName());
			xmlSignatureScope.setScope(scope.getType());
			xmlSignatureScope.setValue(scope.getDescription());

			xmlSignatureScopes.getSignatureScope().add(xmlSignatureScope);
		}
		xmlSignature.setSignatureScopes(xmlSignatureScopes);
	}

	private XmlBasicSignatureType getXmlBasicSignatureType(XmlSignature xmlSignature) {
		XmlBasicSignatureType xmlBasicSignature = xmlSignature.getBasicSignature();
		if (xmlBasicSignature == null) {

			xmlBasicSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();
		}
		return xmlBasicSignature;
	}

	/**
	 * This method verifies the cryptographic integrity of the signature: the references are identified, their digest is checked and then the signature itself. The result of these
	 * verifications is transformed to the JAXB representation.
	 *
	 * @param signature    Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @param xmlSignature The JAXB object containing all diagnostic data pertaining to the signature
	 */
	private void performSignatureCryptographicValidation(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		final SignatureCryptographicVerification scv = signature.checkSignatureIntegrity();
		final XmlBasicSignatureType xmlBasicSignature = getXmlBasicSignatureType(xmlSignature);
		xmlBasicSignature.setReferenceDataFound(scv.isReferenceDataFound());
		xmlBasicSignature.setReferenceDataIntact(scv.isReferenceDataIntact());
		xmlBasicSignature.setSignatureIntact(scv.isSignatureIntact());
		xmlBasicSignature.setSignatureValid(scv.isSignatureValid());
		final XmlReferencesType xmlReferences = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlReferencesType();
		final List<XmlReference> referenceList = xmlReferences.getReference();
		final List<SignatureCryptographicVerification.SignatureReference> signatureReferences = scv.getSignatureReferences();
		for (final SignatureCryptographicVerification.SignatureReference signatureReference : signatureReferences) {

			final XmlReference xmlReference = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlReference();
			xmlReference.setType(signatureReference.getType());
			xmlReference.setUri(signatureReference.getUri());
			xmlReference.setReferenceDataFound(signatureReference.isReferenceDataFound());
			xmlReference.setReferenceDataIntact(signatureReference.isReferenceDataIntact());
			final Boolean dataObjectFormat = signatureReference.isDataObjectFormat();
			if (dataObjectFormat != null) { // only for XAdES
				xmlReference.setDataObjectFormat(dataObjectFormat);
			}
			final List<SignatureCryptographicVerification.SignatureReference> manifestReferences = signatureReference.getManifestReferences();
			if (manifestReferences != null) {

				final XmlReferencesType xmlManifestReferences = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlReferencesType();
				final List<XmlReference> manifestReferenceList = xmlManifestReferences.getReference();
				for (final SignatureCryptographicVerification.SignatureReference manifestReference : manifestReferences) {

					final XmlReference xmlManifestReference = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlReference();
					xmlManifestReference.setType(manifestReference.getType());
					xmlManifestReference.setUri(manifestReference.getUri());
					xmlManifestReference.setRealUri(manifestReference.getRealUri());
					xmlManifestReference.setReferenceDataFound(manifestReference.isReferenceDataFound());
					xmlManifestReference.setReferenceDataIntact(manifestReference.isReferenceDataIntact());
					xmlManifestReference.setDigestMethod(manifestReference.getDigestMethod());
					manifestReferenceList.add(xmlManifestReference);
				}
				xmlReference.setManifestReferences(xmlManifestReferences);
			}
			referenceList.add(xmlReference);
		}
		xmlBasicSignature.setReferences(xmlReferences);

		xmlSignature.setBasicSignature(xmlBasicSignature);
		if (!scv.getErrorMessage().isEmpty()) {

			xmlSignature.setErrorMessage(scv.getErrorMessage());
		}
	}

	/**
	 * This method finds the signing certificate and creates its JAXB object representation. This is the signing certificate used to produce the main signature (signature being
	 * analysed). If the signingToken is null (the signing certificate was not found) then Id is set to 0.
	 *
	 * @param signature    Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @param xmlSignature The JAXB object containing all diagnostic data pertaining to the signature
	 * @return
	 */
	private CertificateValidity dealSigningCertificate(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		final XmlSigningCertificateType xmlSignCertType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSigningCertificateType();
		signature.checkSigningCertificate();
		final CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		if (theCertificateValidity != null) {

			final CertificateToken signingCertificateToken = theCertificateValidity.getCertificateToken();
			if (signingCertificateToken != null) {

				xmlSignCertType.setId(signingCertificateToken.getDSSId());
			}
			xmlSignCertType.setAttributePresent(theCertificateValidity.isAttributePresent());
			xmlSignCertType.setDigestValuePresent(theCertificateValidity.isDigestPresent());
			xmlSignCertType.setDigestValueMatch(theCertificateValidity.isDigestEqual());
			final boolean issuerSerialMatch = theCertificateValidity.isSerialNumberEqual() && theCertificateValidity.isDistinguishedNameEqual();
			xmlSignCertType.setIssuerSerialMatch(issuerSerialMatch);
			xmlSignCertType.setSigned(theCertificateValidity.getSigned());
			xmlSignature.setSigningCertificate(xmlSignCertType);
		}
		return theCertificateValidity;
	}

	/**
	 * This method creates the SigningCertificate element for the current token.
	 *
	 * @param issuerCertificateToken the issuer certificate of the current token
	 * @return
	 */
	protected XmlSigningCertificateType xmlForSigningCertificate(final CertificateToken issuerCertificateToken) {

		if (issuerCertificateToken != null) {

			final XmlSigningCertificateType xmlSignCertType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSigningCertificateType();

			xmlSignCertType.setId(issuerCertificateToken.getDSSId());
			return xmlSignCertType;
		}
		return null;
	}

	/**
	 * @return {@code SignatureScopeFinder<XAdESSignature>}
	 */
	public SignatureScopeFinder<XAdESSignature> getXadesSignatureScopeFinder() {
		return xadesSignatureScopeFinder;
	}

	/**
	 * Set the SignatureScopeFinder to use for XML signatures
	 *
	 * @param xadesSignatureScopeFinder
	 */
	public void setXadesSignatureScopeFinder(SignatureScopeFinder<XAdESSignature> xadesSignatureScopeFinder) {
		this.xadesSignatureScopeFinder = xadesSignatureScopeFinder;
	}

	public SignatureScopeFinder<CAdESSignature> getCadesSignatureScopeFinder() {
		return cadesSignatureScopeFinder;
	}

	/**
	 * Set the SignatureScopeFinder to use for CMS signatures
	 *
	 * @param cadesSignatureScopeFinder
	 */
	public void setCadesSignatureScopeFinder(SignatureScopeFinder<CAdESSignature> cadesSignatureScopeFinder) {
		this.cadesSignatureScopeFinder = cadesSignatureScopeFinder;
	}

	public SignatureScopeFinder<PAdESSignature> getPadesSignatureScopeFinder() {
		return padesSignatureScopeFinder;
	}

	/**
	 * Set the SignatureScopeFinder to use for PDF signatures
	 *
	 * @param padesSignatureScopeFinder
	 */
	public void setPadesSignatureScopeFinder(SignatureScopeFinder<PAdESSignature> padesSignatureScopeFinder) {
		this.padesSignatureScopeFinder = padesSignatureScopeFinder;
	}

	protected abstract SignatureScopeFinder getSignatureScopeFinder();

	@Override
	public DocumentValidator getNextValidator() {
		return null;
	}

	/**
	 * This method allows to define the sequence of the validator related to a document to validate. It's only used with ASiC-E container.
	 *
	 * @param validator {@code SignedDocumentValidator} corresponding to the next signature with in the contained.
	 */
	public void setNextValidator(final DocumentValidator validator) {
		throw new DSSUnsupportedOperationException("This method is not applicable in this context!");
	}

	@Override
	public DocumentValidator getSubordinatedValidator() {
		return null;
	}

	/**
	 * @param name
	 * @param constraint
	 */
	public void defineCustomConstraint(final String name, final Constraint constraint) {

		if (DSSUtils.isBlank(name)) {
			throw new DSSNullException(String.class, "name", "The constraint should have a well defined name!");
		}
		if (constraint == null) {
			throw new DSSNullException(Constraint.class, "constraint");
		}
		if (customConstraintMap == null) {
			customConstraintMap = new HashMap<String, Constraint>();
		}
		customConstraintMap.put(name, constraint);
	}
}