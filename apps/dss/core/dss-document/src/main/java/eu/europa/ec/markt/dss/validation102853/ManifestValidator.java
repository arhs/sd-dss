package eu.europa.ec.markt.dss.validation102853;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNotApplicableMethodException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.ObjectFactory;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlBasicSignatureType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlDetachedContents;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlReference;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlReferencesType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignature;
import eu.europa.ec.markt.dss.validation102853.policy.EtsiValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.xades.OfflineResolver;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

/**
 * This class allows to validate only a manifest file. The signature validation is not implemented within this class.
 *
 * @author Robert Bielecki
 */
public class ManifestValidator implements DocumentValidator {

	/*
	 * The factory used to create DiagnosticData
	 */
	protected static final ObjectFactory DIAGNOSTIC_DATA_OBJECT_FACTORY = new ObjectFactory();
	protected final DSSDocument dssSignatureDocument;
	protected DiagnosticData jaxbDiagnosticData; // JAXB object
	/**
	 * This list contains the list of signatures
	 */
	protected List<AdvancedSignature> signatures = null;
	protected Document signatureDocument;
	/**
	 * This {@code List} contains the documents to be validated against the manifest file.
	 */
	protected List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();


	/**
	 * The default constructor for XMLDocumentValidator. The created instance is initialised with default {@code XPathQueryHolder} and {@code XAdES111XPathQueryHolder}.
	 *
	 * @param dssSignatureDocument The instance of {@code DSSDocument} to validate representing the manifest file
	 */
	public ManifestValidator(final DSSDocument dssSignatureDocument) {

		this.dssSignatureDocument = dssSignatureDocument;
		this.signatureDocument = DSSXMLUtils.buildDOM(dssSignatureDocument);
	}

	@Override
	public DSSDocument getDocument() {
		return null;
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
	public List<AdvancedSignature> getSignatures() {

		if (signatures != null) {
			return signatures;
		}
		signatures = new ArrayList<AdvancedSignature>();
		final NodeList signatureNodeList = DSSXMLUtils.getNodeList(signatureDocument, "//ds:Signature[not(parent::xades:CounterSignature)]");
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final XAdESSignature xadesSignature = new XAdESSignature(signatureEl, null);
			xadesSignature.setDetachedContents(detachedContents);
			signatures.add(xadesSignature);
		}
		return signatures;
	}

	@Override
	public void setCertificateVerifier(final CertificateVerifier certVerifier) {
		throw new DSSNotApplicableMethodException(ManifestValidator.class);
	}

	@Override
	public void defineSigningCertificate(final X509Certificate x509Certificate) {
		throw new DSSNotApplicableMethodException(ManifestValidator.class);
	}

	@Override
	public void setPolicyFile(File policyDocument) {

	}

	@Override
	public void setPolicyFile(String signatureId, File policyDocument) {

	}

	@Override
	public void setProcessExecutor(ProcessExecutor processExecutor) {

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

	@Override
	public Reports validateDocument(final InputStream policyDataStream) {

		final Document validationPolicyDom = ValidationResourceManager.loadPolicyData(policyDataStream);
		return validateDocument(validationPolicyDom);
	}

	@Override
	public Reports validateDocument(final Document validationPolicyDom) {

		final ValidationPolicy validationPolicy = new EtsiValidationPolicy(validationPolicyDom);
		return validateDocument(validationPolicy);
	}

	@Override
	public Reports validateDocument(final ValidationPolicy validationPolicy) {

		jaxbDiagnosticData = DIAGNOSTIC_DATA_OBJECT_FACTORY.createDiagnosticData();

		// To cope with tests it can be interesting to always keep the same file name within the reports (without the path).
		String absolutePath = dssSignatureDocument.getAbsolutePath();
		if (CertificateIdentifier.isUniqueIdentifier()) {

			absolutePath = dssSignatureDocument.getName();
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
		// For each signature present in the document to be validated the extraction of diagnostic data is launched.
		final List<AdvancedSignature> allSignatureList = getSignatures();
		for (final AdvancedSignature signature : allSignatureList) {

			if (signature instanceof XAdESSignature) {

				final XmlSignature xmlSignature = validateManifest((XAdESSignature) signature);
				jaxbDiagnosticData.getSignature().add(xmlSignature);
			}
		}

		final Document diagnosticDataDom = ValidationResourceManager.convert(jaxbDiagnosticData);
		DSSXMLUtils.printDocument(diagnosticDataDom, System.out);
		return null;
	}

	@Override
	public DocumentValidator getNextValidator() {
		return null;
	}

	@Override
	public DocumentValidator getSubordinatedValidator() {
		return null;
	}

	@Override
	public DSSDocument removeSignature(String signatureId) throws DSSException {
		throw new DSSNotApplicableMethodException(ManifestValidator.class);
	}

	/**
	 * Main method for validating a manifest. The diagnostic data is extracted.
	 *
	 * @param xadesSignature Signature to be validated (mast be XAdES, CAdES). // TODO-Bob (07/12/2015):
	 * @return The JAXB object containing all diagnostic data pertaining to the signature
	 */
	private XmlSignature validateManifest(final XAdESSignature xadesSignature) throws DSSException {

		final XmlSignature xmlSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignature();
		try {

			xmlSignature.setId(xadesSignature.getId());
			final SignatureCryptographicVerification signatureCryptographicVerification = dealWithManifest(xadesSignature);
			final XmlBasicSignatureType xmlBasicSignature = getXmlBasicSignatureType(xmlSignature);
			xmlBasicSignature.setReferenceDataFound(signatureCryptographicVerification.isReferenceDataFound());
			xmlBasicSignature.setReferenceDataIntact(signatureCryptographicVerification.isReferenceDataIntact());
			xmlBasicSignature.setSignatureIntact(signatureCryptographicVerification.isSignatureIntact());
			xmlBasicSignature.setSignatureValid(signatureCryptographicVerification.isSignatureValid());
			final XmlReferencesType xmlReferences = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlReferencesType();
			final List<XmlReference> referenceList = xmlReferences.getReference();
			final List<SignatureCryptographicVerification.SignatureReference> signatureReferences = signatureCryptographicVerification.getSignatureReferences();
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
		} catch (Exception e) {

			// Any raised error is just logged and the process continues with the next signature.
			//			LOG.warn(e.getMessage(), e);
			//			addErrorMessage(xmlSignature, e);
		}
		return xmlSignature;
	}

	private XmlBasicSignatureType getXmlBasicSignatureType(final XmlSignature xmlSignature) {

		XmlBasicSignatureType xmlBasicSignature = xmlSignature.getBasicSignature();
		if (xmlBasicSignature == null) {

			xmlBasicSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlBasicSignatureType();
		}
		return xmlBasicSignature;
	}

	/**
	 * This method deals with the basic signature data. The retrieved information is transformed to the JAXB object. The signing certificate token is returned if found.
	 *
	 * @param signature {@code XAdESSignature} signature to be validated
	 */
	private SignatureCryptographicVerification dealWithManifest(final XAdESSignature signature) {

		final Element rootElement = signatureDocument.getDocumentElement();

		DSSXMLUtils.setIDIdentifier(rootElement);
		DSSXMLUtils.recursiveIdBrowse(rootElement);
		try {

			final SignatureCryptographicVerification signatureCryptographicVerification = new SignatureCryptographicVerification();

			final Element signatureElement = signature.getSignatureElement();
			final XMLSignature santuarioSignature = new XMLSignature(signatureElement, "");
			final OfflineResolver offlineResolver = new OfflineResolver(detachedContents);
			santuarioSignature.addResourceResolver(offlineResolver);

			final SignedInfo signedInfo = santuarioSignature.getSignedInfo();

			final int length = signedInfo.getLength();
			for (int ii = 0; ii < length; ii++) {

				final SignatureCryptographicVerification.SignatureReference signatureReference = signatureCryptographicVerification.addReference();
				final Reference reference = signedInfo.item(ii);
				if (reference.typeIsReferenceToManifest()) {

					final byte[] referencedBytes = reference.getReferencedBytes();
					final Document manifestDocument = DSSXMLUtils.buildDOM(referencedBytes);
					final Manifest manifest = getManifestQuietly(manifestDocument);
					if (manifest != null) {

						manifest.addResourceResolver(offlineResolver);
						final int manifestReferenceNumber = manifest.getLength();
						for (int jj = 0; jj < manifestReferenceNumber; jj++) {

							final Reference manifestItem = manifest.item(jj);
							final String manifestItemType = manifestItem.getType();
							boolean manifestReferenceVerified;
							try {
								manifestReferenceVerified = manifestItem.verify();
							} catch (final Exception e) {
								manifestReferenceVerified = false;
							}
							if (manifestReferenceVerified) {

								final SignatureCryptographicVerification.SignatureReference manifestReference = signatureReference.addManifestReference();
								if (manifestItemType != null && !manifestItemType.isEmpty()) {
									manifestReference.setType(manifestItemType);
								}
								manifestReference.setUri(manifestItem.getURI());
								manifestReference.setRealUri(offlineResolver.getLastUri());
								manifestReference.setReferenceDataFound(manifestItem.getReferenceData() != null);
								manifestReference.setReferenceDataIntact(manifestReferenceVerified);
								final MessageDigestAlgorithm messageDigestAlgorithm = manifestItem.getMessageDigestAlgorithm();
								final String algorithm = messageDigestAlgorithm.getAlgorithm().getAlgorithm();
								manifestReference.setDigestMethod(DigestAlgorithm.forName(algorithm).getName());
							}
							//						System.out.println("--> " + DSSUtils.base64Encode(manifestItem.getDigestValue()));
						}
					}
					if (signatureReference.getManifestReferences() == null) {
						if (detachedContents != null) {
							for (final DSSDocument detachedContent : detachedContents) {

								final SignatureCryptographicVerification.SignatureReference manifestReference = signatureReference.addManifestReference();
								manifestReference.setRealUri(detachedContent.getName());
							}
						}
					}
				}
			}
			return signatureCryptographicVerification;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private Manifest getManifestQuietly(final Document manifestDocument) throws XMLSecurityException {

		try {
			return new Manifest(manifestDocument.getDocumentElement(), null);
		} catch (XMLSecurityException e) {
			//			LOG.error("Manifest instantiation failed: ", e);
		}
		return null;
	}
}