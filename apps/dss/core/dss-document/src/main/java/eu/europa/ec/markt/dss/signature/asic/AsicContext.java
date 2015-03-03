/*
 * SD-DSS - Digital Signature Services
 *
 * Copyright (C) 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * Developed by: 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * This file is part of the "https://github.com/arhs/sd-dss" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "SD-DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.asic;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.ASiCNamespaces;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.ASiCParameters;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.cades.CAdESService;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.DocumentValidator;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;

/**
 * This class is used during the ASiC signature creation and extension.
 *
 * @author Robert Bielecki
 */
public class AsicContext {

	private final static String META_INF = "META-INF/";

	private final static String ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE = META_INF + "signatures.xml";
	private final static String ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE = META_INF + "signatures001.xml";
	private final static String ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE = META_INF + "signature.p7s";
	private final static String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	public final static String ASICS_NS = "asic:XAdESSignatures";

	private final SignatureForm containerForm;
	private final SignatureLevel containerLevel;

	private final SignatureForm subordinatedForm;
	private final SignatureLevel subordinatedLevel;
	private final SignaturePackaging subordinatedPackaging;

	private final ASiCService asicService;
	private final SignatureParameters subordinatedParameters;
	private final DocumentSignatureService subordinatedService;

	private final DocumentValidator containerValidator; // null it the document to sign is not an ASiC container
	private DocumentValidator subordinatedValidator = null;

	private DSSDocument subordinatedSignature = null;
	private DSSDocument subordinatedToSignDocument = null;

	private DSSDocument detachedContents;
	private DSSDocument existingContainer = null;
	private String signatureFileName;
	private DigestAlgorithm manifestDigestAlgorithm;

	/**
	 * This constructor initiates the following fields:<br>
	 * {@code containerForm} based on {@code SignatureForm}: ASiC container: S or E<br>
	 * {@code containerLevel} based on {@code SignatureLevel}: ASiC container: ASiC_S_BASELINE_B, ASiC_S_BASELINE_T...<br>
	 * {@code subordinatedForm} based on {@code SignatureForm} of the ASiC container: CAdES or XAdES<br>
	 * {@code subordinatedLevel} based on {@code SignatureLevel} of the ASiC container: CAdES_BASELINE_B, XAdES_BASELINE_T...<br>
	 */
	public AsicContext(final ASiCService asicService, final DSSDocument toSignDocument, final SignatureParameters parameters) {

		assertAsicServiceNotNull(asicService);
		this.asicService = asicService;
		assertToSignDocumentNotNull(toSignDocument);
		assertSignatureParametersNotNull(parameters);
		final ASiCParameters asicParameters = parameters.aSiC();
		containerForm = asicParameters.getContainerForm();
		assertContainerFormNotNull(containerForm);
		assertRightContainerForm(containerForm);
		containerLevel = parameters.getSignatureLevel();
		assertContainerLevelNotNull(containerLevel);
		subordinatedForm = asicParameters.getUnderlyingForm();
		assertSubordinatedFormNotNull(subordinatedForm);

		this.subordinatedLevel = getSubordinatedLevel(containerLevel, subordinatedForm);
		subordinatedPackaging = isCadesFrom() ? SignaturePackaging.DETACHED : SignaturePackaging.ENVELOPED;
		manifestDigestAlgorithm = parameters.getDigestAlgorithm();

		signatureFileName = getSignatureFileName(asicParameters.getSignatureFileName());

		subordinatedService = createSubordinatedService();

		containerValidator = getAsicValidator(toSignDocument);
		if (isExistingContainer()) {

			existingContainer = toSignDocument;
			basedOnExistingContainer(parameters);
		} else { // new container
			parameters.setDetachedContent(toSignDocument); // The content to sign is automatically set to 'toSignDocument'
			basedOnNewContainer(parameters);
		}
		if (isXadesFrom()) {
			prepareReferences(parameters);
		}
		// The subordinated parameters are prepared at the end to take into account all elements
		subordinatedParameters = createSubordinatedParameters(parameters);
	}

	private void assertSignatureParametersNotNull(final SignatureParameters parameters) {
		if (parameters == null) {
			throw new DSSNullException(SignatureParameters.class);
		}
	}

	private void basedOnNewContainer(final SignatureParameters parameters) {

		detachedContents = parameters.getDetachedContent();
		if (isAsice()) {
			if (isCadesFrom()) {
				subordinatedToSignDocument = createAsicManifest();
			} else { // XAdES form
				subordinatedToSignDocument = createAsicXadesSignaturesEnvelop();
			}
		} else { // ASiC-S
			if (isCadesFrom()) {

				subordinatedToSignDocument = parameters.getDetachedContent();
			} else {
				subordinatedToSignDocument = createAsicXadesSignaturesEnvelop();
			}
		}
	}

	private void basedOnExistingContainer(final SignatureParameters parameters) {

		subordinatedValidator = containerValidator.getSubordinatedValidator();
		// assertContainerFormCompliesToSignDocument()
		subordinatedSignature = subordinatedValidator.getDocument();
		if (isAsice()) {

			detachedContents = getExistingAsiceDetachedContents();
			if (isCadesFrom()) {
				subordinatedToSignDocument = createAsicManifest(); // In the current implementation an ASiC manifest file is always created
			} else { // XAdES form
				// A new asic:XAdESSignatures element is always created. It could be possible to add signatures to the existing one: the process to be set
				subordinatedToSignDocument = createAsicXadesSignaturesEnvelop();
			}
		} else { // ASiC-S

			subordinatedToSignDocument = subordinatedSignature;
			detachedContents = getExistingAsicsDetachedContents();
		}
	}

	private DSSDocument getExistingAsicsDetachedContents() {

		final List<DSSDocument> detachedContentsList = subordinatedValidator.getDetachedContents();
		if (detachedContentsList.size() != 1) {
			throw new DSSException("ASiC-S must contain only one data object!");
		}
		return detachedContentsList.get(0); // ASiC-S: only one document
	}

	private DSSDocument getExistingAsiceDetachedContents() {

		final List<DSSDocument> detachedContents = subordinatedValidator.getDetachedContents();
		if (detachedContents.size() == 0) {
			throw new DSSException("ASiC-E must contain at least one data object!");
		}
		return detachedContents.get(0);
	}

	public boolean isAsics() {
		return containerForm == SignatureForm.ASiC_S;
	}

	public boolean isAsice() {
		return containerForm == SignatureForm.ASiC_E;
	}

	public SignatureLevel getSubordinatedLevel() {
		return subordinatedLevel;
	}

	public boolean isCadesFrom() {
		return subordinatedForm == SignatureForm.CAdES;
	}

	public boolean isXadesFrom() {
		return subordinatedForm == SignatureForm.XAdES;
	}

	public boolean isExistingContainer() {
		return containerValidator != null;
	}

	public SignaturePackaging getSubordinatedPackaging() {

		return subordinatedPackaging;
	}

	public DSSDocument getSubordinatedToSignDocument() {

		return subordinatedToSignDocument;
	}

	public SignatureParameters getSubordinatedParameters() {

		return subordinatedParameters;
	}

	public DocumentSignatureService getSubordinatedService() {

		return subordinatedService;
	}

	public DSSDocument getDetachedContents() {

		return detachedContents;
	}

	public DSSDocument getExistingContainer() {

		return existingContainer;
	}

	public String getSignatureFileName() {
		return signatureFileName;
	}

	public DigestAlgorithm getManifestDigestAlgorithm() {
		return manifestDigestAlgorithm;
	}

	public DSSDocument getSubordinatedSignature() {
		return subordinatedSignature;
	}

	public DocumentValidator getSubordinatedValidator() {
		return subordinatedValidator;
	}

	private void assertAsicServiceNotNull(final ASiCService asicService) {
		if (asicService == null) {
			throw new DSSNullException(ASiCService.class);
		}
	}

	private void assertSubordinatedFormNotNull(final SignatureForm subordinatedForm) {
		if (subordinatedForm == null) {
			throw new DSSNullException(SignatureForm.class, "subordinatedForm");
		}
	}

	private void assertContainerLevelNotNull(final SignatureLevel containerLevel) {
		if (containerLevel == null) {
			throw new DSSNullException(SignatureLevel.class, "containerLevel");
		}
	}

	private void assertRightContainerForm(final SignatureForm containerForm) {
		if (SignatureForm.ASiC_E != containerForm && SignatureForm.ASiC_S != containerForm) {
			throw new DSSException("The SignatureForm must be either ASiC_E or ASiC_S but was '" + containerForm + "'!");
		}
	}

	private void assertContainerFormNotNull(final SignatureForm containerForm) {
		if (containerForm == null) {
			throw new DSSNullException(SignatureForm.class, "containerForm");
		}
	}

	private void assertToSignDocumentNotNull(final DSSDocument toSignDocument) {
		if (toSignDocument == null) {
			throw new DSSNullException(DSSDocument.class, "toSignDocument");
		}
	}

	/**
	 * Creates a specific XAdES/CAdES signature parameters on the base of the provided parameters. Forces the signature packaging to
	 * DETACHED for the CAdES form and ENVELOPED for the XAdES form.
	 *
	 * @return new specific instance for XAdES or CAdES
	 */
	private SignatureParameters getParameters() {

		return subordinatedParameters;
	}

	private SignatureParameters createSubordinatedParameters(final SignatureParameters parameters) {

		final SignatureParameters subordinatedParameters = new SignatureParameters(parameters);
		subordinatedParameters.setSignatureLevel(getSubordinatedLevel());
		subordinatedParameters.setSignaturePackaging(getSubordinatedPackaging());
		if (isCadesFrom()) { // The detached contents must be null. In the case of ASiC-E the contents to sign is manifest file passed as parameter. In the case of ASiC-S there the document to sign is passed as parameter
			subordinatedParameters.setDetachedContent(null);
		}
		return subordinatedParameters;
	}

	/**
	 * This method returns the specific service associated with the container: {@code XAdESService} or {@code CAdESService}.
	 *
	 * @return {@code DocumentSignatureService}, the subordinated service
	 */
	private DocumentSignatureService createSubordinatedService() {

		final CertificateVerifier cryptographicSourceProvider = asicService.getCryptographicSourceProvider();
		final DocumentSignatureService subordinatedService;
		if (isCadesFrom()) {
			subordinatedService = new CAdESService(cryptographicSourceProvider);
		} else {
			subordinatedService = new XAdESService(cryptographicSourceProvider);
		}
		subordinatedService.setTspSource(asicService.getTspSource());
		return subordinatedService;
	}

	private static SignatureLevel getSubordinatedLevel(final SignatureLevel containerLevel, final SignatureForm containerForm) {

		final boolean xades = containerForm == SignatureForm.XAdES;
		switch (containerLevel) {

			case ASiC_S_BASELINE_B:
			case ASiC_E_BASELINE_B:
				return xades ? SignatureLevel.XAdES_BASELINE_B : SignatureLevel.CAdES_BASELINE_B;
			case ASiC_S_BASELINE_T:
			case ASiC_E_BASELINE_T:
				return xades ? SignatureLevel.XAdES_BASELINE_T : SignatureLevel.CAdES_BASELINE_T;
			case ASiC_S_BASELINE_LT:
			case ASiC_E_BASELINE_LT:
				return xades ? SignatureLevel.XAdES_BASELINE_LT : SignatureLevel.CAdES_BASELINE_LT;
			case ASiC_S_BASELINE_LTA:
			case ASiC_E_BASELINE_LTA:
				return xades ? SignatureLevel.XAdES_BASELINE_LTA : SignatureLevel.CAdES_BASELINE_LTA;
			default:
				throw new DSSException("Unsupported format: " + containerLevel.name());
		}
	}

	private static DocumentValidator getAsicValidator(final DSSDocument toSignDocument) {

		try { // Check if this is an existing container

			final DocumentValidator documentValidator = SignedDocumentValidator.fromDocument(toSignDocument);
			if (isAsicValidator(documentValidator)) {
				return documentValidator;
			}
		} catch (Exception e) {
			// do nothing
		}
		return null;
	}

	private static boolean isAsicValidator(final DocumentValidator documentValidator) {

		final boolean result = documentValidator != null && (documentValidator instanceof ASiCContainerValidator);
		return result;
	}

	private static DSSDocument createAsicXadesSignaturesEnvelop() {

		final Document document = DSSXMLUtils.buildDOM();
		final Element asicDom = document.createElementNS(ASiCNamespaces.ASiC, ASICS_NS);
		document.appendChild(asicDom);
		final byte[] bytes = DSSXMLUtils.serializeNode(document);
		final DSSDocument contextToSignDocument = new InMemoryDocument(bytes);
		return contextToSignDocument;
	}

	private DSSDocument createAsicManifest() {

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		ASiCService.buildAsicManifest(this, outputStream);
		final DSSDocument contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
		return contextToSignDocument;
	}

	private String getSignatureFileName(final String signatureFileName) {

		if (isAsice()) {
			if (DSSUtils.isNotBlank(signatureFileName)) {
				return META_INF + signatureFileName;
			} else if (subordinatedSignature != null) {
				throw new DSSNullException(String.class, "signatureFileName");
			}
			return isCadesFrom() ? ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE : ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE;
		}
		// ASiC-S: does not matter if it's an existing or new container
		return isCadesFrom() ? ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE : ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE;
	}

	public String getSignatureMimeType() {

		if (isXadesFrom()) {
			return MimeType.XML.getMimeTypeString();
		} else { // CAdES form
			return MimeType.PKCS7.getMimeTypeString();
		}
	}

	private void prepareReferences(final SignatureParameters signatureParameters) {

		List<DSSReference> references = signatureParameters.getReferences();
		if (references != null) {
			return;
		}
		references = new ArrayList<DSSReference>();
		DSSDocument currentDetachedDocument = detachedContents;
		int referenceIndex = 1;
		do {
			//<ds:Reference Id="detached-ref-id" URI="xml_example.xml">
			final DSSReference reference = new DSSReference();
			reference.setId("r-id-" + referenceIndex++);
			final String currentDetachedDocumentName = currentDetachedDocument.getName();
			if (currentDetachedDocumentName == null) {
				throw new DSSException("The name of a detached document cannot be null!");
			}
			reference.setUri(currentDetachedDocumentName);
			reference.setContents(currentDetachedDocument);
			reference.setDigestMethodAlgorithm(signatureParameters.getDigestAlgorithm());

			references.add(reference);
			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);
		signatureParameters.setReferences(references);
	}
}
