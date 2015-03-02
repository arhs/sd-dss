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

/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/trunk/buildtools/src/main/resources/eclipse/dss-java-code-template.xml $
 * $Revision: 672 $
 * $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * $Author: hiedelch $
 */
package eu.europa.ec.markt.dss.signature.asic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.ASiCNamespaces;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.ASiCParameters;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.DocumentValidator;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCCMSDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;

/**
 * Implementation of {@code DocumentSignatureService} for ASiC-S and -E containers. It allows the creation of containers based on XAdES or CAdES standard.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public class ASiCService extends AbstractSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCService.class);

	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
	private final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_ASICS_METAINF_XADES_SIGNATURE = META_INF + "signatures.xml";
	private final static String ZIP_ENTRY_ASICE_METAINF_XADES_SIGNATURE = META_INF + "signatures001.xml";
	private final static String ZIP_ENTRY_ASICS_METAINF_CADES_SIGNATURE = META_INF + "signature.p7s";
	private final static String ZIP_ENTRY_ASICE_METAINF_CADES_SIGNATURE = META_INF + "signature001.p7s";

	private final static String ASICS_EXTENSION = ".asics"; // can be ".scs"
	private final static String ASICE_EXTENSION = ".asice"; // can be ".sce"
	public final static String ASICS_NS = "asic:XAdESSignatures";

	/**
	 * This is the constructor to create an instance of the {@code ASiCService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public ASiCService(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		LOG.debug("+ ASiCService created");
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final SignatureParameters underlyingParameters = getParameters(toSignDocument, parameters);

		// toSignDocument can be a simple file or an ASiC container
		final DSSDocument contextToSignDocument = prepare(toSignDocument, underlyingParameters);
		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());
		final DocumentSignatureService underlyingService = getSpecificService(underlyingParameters);
		return underlyingService.getDataToSign(contextToSignDocument, underlyingParameters);
	}

	/**
	 * ETSI TS 102 918 v1.2.1 (2012-02) <br />
	 * <p>
	 * Contents of Container ( 6.2.2 )
	 * </p>
	 * <ul>
	 * <li>The file extension ".asics" should be used .</li>
	 * <li>The root element of each signature content shall be either &lt;asic:XadESSignatures&gt; as specified in clause
	 * A.5. Its the recommended format</li>
	 * <li>The comment field in the ZIP header may be used to identify the type of the data object within the container.
	 * <br />
	 * If this field is present, it should be set with "mimetype=" followed by the mime type of the data object held in
	 * the signed data object</li>
	 * <li>The mimetype file can be used to support operating systems that rely on some content in specific positions in
	 * a file.<br />
	 * <ul>
	 * <li>It has to be the first entry in the archive.</li>
	 * <li>It cannot contain "Extra fields".</li>
	 * <li>It cannot be compressed or encrypted inside the ZIP file</li>
	 * </ul>
	 * </li>
	 * </ul>
	 */
	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		// Signs the toSignDocument first
		SignatureParameters underlyingParameters = getParameters(toSignDocument, parameters);

		DSSDocument contextToSignDocument = prepare(toSignDocument, underlyingParameters);
		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		parameters.aSiC().setEnclosedSignature(asicParameters.getEnclosedSignature());

		final DocumentSignatureService underlyingService = getSpecificService(underlyingParameters);
		final DSSDocument signature = underlyingService.signDocument(contextToSignDocument, underlyingParameters, signatureValue);

		// ASiC-S: copy detached document from underlyingParameters to new underlyingParameters!
		DSSDocument detachedContent = null;
		if (isAsics(asicParameters)) {
			detachedContent = underlyingParameters.getDetachedContent();
		}
		underlyingParameters = getParameters(toSignDocument, parameters);
		if (isAsics(asicParameters)) {
			underlyingParameters.setDetachedContent(detachedContent);
		}
		DSSDocument existingContainer = null;
		final boolean signingContainer = asicParameters.getEnclosedSignature() != null;
		if (signingContainer) {
			existingContainer = toSignDocument;
		}
		if (isAsice(asicParameters) && isCAdESForm(asicParameters)) {
			if (!signingContainer) {
				contextToSignDocument = toSignDocument;
			} else {
				contextToSignDocument = parameters.getDetachedContent();
			}
		}
		if (isXAdESForm(asicParameters)) {
			if (!signingContainer) {
				contextToSignDocument = toSignDocument;
			} else if (isAsics(asicParameters)) {
				contextToSignDocument = detachedContent;
			} else {
				contextToSignDocument = parameters.getDetachedContent();
			}
		}
		final InMemoryDocument newContainer = buildASiCContainer(contextToSignDocument, existingContainer, underlyingParameters, signature);
		parameters.setDeterministicId(null);
		return newContainer;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		if (signingToken == null) {
			throw new DSSNullException(SignatureTokenConnection.class);
		}
		final byte[] dataToSign = getDataToSign(toSignDocument, parameters);
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry privateKeyEntry = parameters.getPrivateKeyEntry();
		final byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKeyEntry);
		final DSSDocument dssDocument = signDocument(toSignDocument, parameters, signatureValue);
		return dssDocument;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final SignatureParameters parameters) throws DSSException {

		final DocumentValidator validator = SignedDocumentValidator.fromDocument(toExtendDocument);
		final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
		final DocumentSignatureService specificService = getSpecificService(parameters);
		specificService.setTspSource(tspSource);

		final SignatureParameters xadesParameters = getParameters(toSignDocument, parameters);
		final DSSDocument detachedContent = parameters.getDetachedContent();
		final DSSDocument detachedContents = getDetachedContents(subordinatedValidator, detachedContent);
		xadesParameters.setDetachedContent(detachedContents);
		final DSSDocument signature = subordinatedValidator.getDocument();
		final DSSDocument signedDocument = specificService.extendDocument(signature, xadesParameters);

		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		final ZipOutputStream zipOutputStream = new ZipOutputStream(output);
		final ZipInputStream zipInputStream = new ZipInputStream(toExtendDocument.openStream());
		ZipEntry entry;
		while ((entry = getNextZipEntry(zipInputStream)) != null) {

			final String name = entry.getName();
			final ZipEntry newEntry = new ZipEntry(name);
			if (ASiCContainerValidator.isMimetype(name)) {

				storeMimetype(parameters.aSiC(), zipOutputStream);
			} else if (ASiCContainerValidator.isXAdES(name) || ASiCContainerValidator.isCAdES(name)) {

				createZipEntry(zipOutputStream, newEntry);
				final InputStream inputStream = signedDocument.openStream();
				DSSUtils.copy(inputStream, zipOutputStream);
				DSSUtils.closeQuietly(inputStream);
			} else {

				createZipEntry(zipOutputStream, newEntry);
				DSSUtils.copy(zipInputStream, zipOutputStream);
			}
		}
		DSSUtils.closeQuietly(zipInputStream);
		DSSUtils.closeQuietly(zipOutputStream);
		return new InMemoryDocument(output.toByteArray());
	}

	/**
	 * Only in the case of ASiC-S
	 *
	 * @param underlyingParameters  {@code SignatureParameters}
	 * @param subordinatedValidator {@code DocumentValidator}
	 */
	private void copyDetachedContent(final SignatureParameters underlyingParameters, final DocumentValidator subordinatedValidator) {

		final List<DSSDocument> detachedContents = subordinatedValidator.getDetachedContents();
		for (final DSSDocument detachedDocument : detachedContents) {

			underlyingParameters.setDetachedContent(detachedDocument);
			return;
		}
	}

	private InMemoryDocument buildASiCContainer(final DSSDocument toSignDocument, DSSDocument existingContainer, final SignatureParameters underlyingParameters,
	                                            final DSSDocument signature) {

		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		final boolean asice = isAsice(asicParameters);
		final boolean cadesForm = isCAdESForm(asicParameters);

		final String toSignDocumentName = toSignDocument.getName();

		final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		final ZipOutputStream zipOutputStream = new ZipOutputStream(outBytes);
		if (asice && existingContainer != null) {

			copyZipContent(existingContainer, zipOutputStream);
		} else {

			storeZipComment(asicParameters, zipOutputStream, toSignDocumentName);

			storeMimetype(asicParameters, zipOutputStream);
		}
		storeSignedFiles(toSignDocument, zipOutputStream);

		storesSignature(asicParameters, signature, zipOutputStream);

		if (asice && cadesForm) {
			storeAsicManifest(underlyingParameters, toSignDocument, zipOutputStream);
		}
		DSSUtils.close(zipOutputStream);

		final InMemoryDocument asicContainer = createASiCContainer(asicParameters, outBytes, toSignDocumentName);
		return asicContainer;
	}

	private void copyZipContent(DSSDocument toSignAsicContainer, ZipOutputStream zipOutputStream) {

		final InputStream inputStream = toSignAsicContainer.openStream();
		final ZipInputStream zipInputStream = new ZipInputStream(inputStream);
		for (ZipEntry entry = getNextZipEntry(zipInputStream); entry != null; entry = getNextZipEntry(zipInputStream)) {

			createZipEntry(zipOutputStream, entry);
			DSSUtils.copy(zipInputStream, zipOutputStream);
		}
		DSSUtils.closeQuietly(zipInputStream);
	}

	private void storeAsicManifest(final SignatureParameters underlyingParameters, final DSSDocument detachedDocument, final ZipOutputStream outZip) {

		final String signatureName = getSignatureFileName(underlyingParameters.aSiC());
		final int indexOfSignature = signatureName.indexOf("signature");
		String suffix = signatureName.substring(indexOfSignature + "signature".length());
		final int lastIndexOf = suffix.lastIndexOf(".");
		suffix = suffix.substring(0, lastIndexOf);
		final String asicManifestZipEntryName = META_INF + "ASiCManifest" + suffix + ".xml";
		final ZipEntry entrySignature = new ZipEntry(asicManifestZipEntryName);
		createZipEntry(outZip, entrySignature);

		buildAsicManifest(underlyingParameters, detachedDocument, outZip);
	}

	private static void createZipEntry(final ZipOutputStream outZip, final ZipEntry entrySignature) throws DSSException {

		try {
			outZip.putNextEntry(entrySignature);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private InMemoryDocument createASiCContainer(final ASiCParameters asicParameters, final ByteArrayOutputStream outBytes, final String toSignDocumentName) {

		final byte[] documentBytes = outBytes.toByteArray();
		final SignatureForm containerForm = asicParameters.getContainerForm();
		final boolean asics = SignatureForm.ASiC_S.equals(containerForm);
		final String extension = asics ? ASICS_EXTENSION : ASICE_EXTENSION;
		final String name = toSignDocumentName != null ? toSignDocumentName + extension : null;
		final MimeType mimeType = asics ? MimeType.ASICS : MimeType.ASICE;
		return new InMemoryDocument(documentBytes, name, mimeType);
	}

	private void storesSignature(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) {

		if (isXAdESForm(asicParameters)) {

			buildXAdES(asicParameters, signature, outZip);
		} else if (isCAdESForm(asicParameters)) {

			buildCAdES(asicParameters, signature, outZip);
		} else {
			throw new DSSException("ASiC signature form must be XAdES or CAdES!");
		}
	}

	private boolean isCAdESForm(final ASiCParameters asicParameters) {

		final SignatureForm underlyingForm = asicParameters.getUnderlyingForm();
		return SignatureForm.CAdES.equals(underlyingForm);
	}

	private boolean isXAdESForm(final ASiCParameters asicParameters) {
		final SignatureForm underlyingForm = asicParameters.getUnderlyingForm();
		return SignatureForm.XAdES.equals(underlyingForm);
	}

	private void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream outZip, final String toSignDocumentName) {
		// TODO-Bob (02/03/2015):  Check if the toSignDocumentName is mandatory
		if (asicParameters.isZipComment() && DSSUtils.isNotEmpty(toSignDocumentName)) {

			outZip.setComment("mimetype=" + getMimeTypeBytes(asicParameters));
		}
	}

	/**
	 * @param toSignDocument       {@code DSSDocument} can be a simple data file or an existing ASiC container
	 * @param underlyingParameters {@code SignatureParameters}
	 * @return {@code DSSDocument} ???
	 */
	private DSSDocument prepare(final DSSDocument toSignDocument, final SignatureParameters underlyingParameters) {

		DSSDocument contextToSignDocument = toSignDocument;
		final ASiCParameters asicParameters = underlyingParameters.aSiC();
		final boolean asice = isAsice(asicParameters);
		final boolean cadesForm = isCAdESForm(asicParameters);
		final DocumentValidator validator = getAsicValidator(toSignDocument);
		if (isAsicValidator(validator)) {

			// This is already an existing ASiC container; a new signature file should be added.
			final DocumentValidator subordinatedValidator = validator.getSubordinatedValidator();
			final DSSDocument contextSignature = subordinatedValidator.getDocument();
			underlyingParameters.aSiC().setEnclosedSignature(contextSignature);
			if (asice) {

				if (cadesForm) {

					contextToSignDocument = createAsicManifest(underlyingParameters);
					underlyingParameters.setDetachedContent(null);
				} else {

					// Bob (01/03/2015): contextToSignDocument = underlyingParameters.getDetachedContent();
					// A new asic:XAdESSignatures element is always created. It could be possible to add signatures to the existing one: the process to be set
					contextToSignDocument = createAsicXadesSignatures(); // Bob (01/03/2015):
				}
			} else {
				copyDetachedContent(underlyingParameters, subordinatedValidator);
				contextToSignDocument = contextSignature;
			}
			if (!asice && subordinatedValidator instanceof ASiCCMSDocumentValidator) {

				contextToSignDocument = contextSignature;
			}
		} else {

			if (asice && cadesForm) {

				final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				buildAsicManifest(underlyingParameters, toSignDocument, outputStream);
				contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
			} else {

				underlyingParameters.setDetachedContent(contextToSignDocument);
				// TODO-Bob (01/03/2015):
				// If the signature file does not exists yet then a new one is created
				contextToSignDocument = createAsicXadesSignatures();
			}
		}
		if (!cadesForm) {
			prepareReferences(underlyingParameters);
		}
		return contextToSignDocument;
	}

	private static DSSDocument createAsicXadesSignatures() {

		final Document document = DSSXMLUtils.buildDOM();
		final Element asicDom = document.createElementNS(ASiCNamespaces.ASiC, ASICS_NS);
		document.appendChild(asicDom);
		final byte[] bytes = DSSXMLUtils.serializeNode(document);
		final DSSDocument contextToSignDocument = new InMemoryDocument(bytes);
		return contextToSignDocument;
	}

	private static ZipEntry getNextZipEntry(final ZipInputStream zipInputStream) throws DSSException {
		try {
			return zipInputStream.getNextEntry();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private DSSDocument getDetachedContents(final DocumentValidator subordinatedValidator, DSSDocument originalDocument) {

		final List<DSSDocument> detachedContents = subordinatedValidator.getDetachedContents();
		if (DSSUtils.isEmpty(detachedContents)) {

			final List<DSSDocument> detachedContentsList = new ArrayList<DSSDocument>();
			DSSDocument currentDocument = originalDocument;
			do {

				detachedContentsList.add(currentDocument);
				subordinatedValidator.setDetachedContents(detachedContentsList);
				currentDocument = currentDocument.getNextDocument();
			} while (currentDocument != null);
		} else {

			originalDocument = null;
			DSSDocument lastDocument = null;
			for (final DSSDocument currentDocument : detachedContents) {

				if (originalDocument == null) {
					originalDocument = currentDocument;
				} else {
					lastDocument.setNextDocument(currentDocument);
				}
				lastDocument = currentDocument;
			}
		}
		return originalDocument;
	}

	/**
	 * Creates a specific XAdES/CAdES signature parameters on the base of the provided parameters. Forces the signature packaging to
	 * DETACHED for the CAdES form and ENVELOPED for the XAdES form.
	 *
	 * @param toSignDocument
	 * @param parameters     must provide signingToken, PrivateKeyEntry and date
	 * @return new specific instance for XAdES or CAdES
	 */
	private SignatureParameters getParameters(final DSSDocument toSignDocument, final SignatureParameters parameters) {

		final AsicContext asicContext = new AsicContext(toSignDocument, parameters);
		final SignatureParameters underlyingParameters = new SignatureParameters(parameters);
		underlyingParameters.setSignatureLevel(asicContext.getSubordinatedLevel());
		underlyingParameters.setSignaturePackaging(asicContext.getSubordinatedPackaging());
		return underlyingParameters;
	}

	private void prepareReferences(final SignatureParameters signatureParameters) {

		List<DSSReference> references = signatureParameters.getReferences();
		if (references != null) {
			return;
		}
		references = new ArrayList<DSSReference>();
		DSSDocument currentDetachedDocument = signatureParameters.getDetachedContent();
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
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
	}

	private void buildCAdES(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {

		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		createZipEntry(outZip, entrySignature);
		zipWriteBytes(outZip, signature.getBytes());
	}

	private static void zipWriteBytes(final ZipOutputStream outZip, final byte[] bytes) throws DSSException {

		try {
			outZip.write(bytes);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private void storeMimetype(final ASiCParameters asicParameters, final ZipOutputStream outZip) throws DSSException {

		final byte[] mimeTypeBytes = getMimeTypeBytes(asicParameters).getBytes();
		final ZipEntry entryMimetype = getZipEntryMimeType(mimeTypeBytes);

		writeZipEntry(outZip, mimeTypeBytes, entryMimetype);
	}

	private void writeZipEntry(final ZipOutputStream outZip, final byte[] mimeTypeBytes, final ZipEntry entryMimetype) throws DSSException {

		createZipEntry(outZip, entryMimetype);
		zipWriteBytes(outZip, mimeTypeBytes);
	}

	private void storeSignedFiles(final DSSDocument detachedDocument, final ZipOutputStream outZip) throws DSSException {

		DSSDocument currentDetachedDocument = detachedDocument;
		do {

			final String detachedDocumentName = currentDetachedDocument.getName();
			final String name = detachedDocumentName != null ? detachedDocumentName : ZIP_ENTRY_DETACHED_FILE;
			final ZipEntry entryDocument = new ZipEntry(name);
			outZip.setLevel(ZipEntry.DEFLATED);
			try {

				createZipEntry(outZip, entryDocument);
				final InputStream inputStream = currentDetachedDocument.openStream();
				DSSUtils.copy(inputStream, outZip);
				DSSUtils.closeQuietly(inputStream);
			} catch (DSSException e) {
				if (!(e.getCause() instanceof ZipException && e.getCause().getMessage().startsWith("duplicate entry:"))) {
					throw e;
				}
			}
			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);
	}

	private String getMimeTypeBytes(final ASiCParameters asicParameters) {

		final String asicParameterMimeType = asicParameters.getMimeType();
		String mimeTypeBytes;
		if (DSSUtils.isBlank(asicParameterMimeType)) {

			if (isAsice(asicParameters)) {
				mimeTypeBytes = MimeType.ASICE.getMimeTypeString();
			} else {
				mimeTypeBytes = MimeType.ASICS.getMimeTypeString();
			}
		} else {
			mimeTypeBytes = asicParameterMimeType;
		}
		return mimeTypeBytes;
	}

	private ZipEntry getZipEntryMimeType(final byte[] mimeTypeBytes) {

		final ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
		entryMimetype.setMethod(ZipEntry.STORED);
		entryMimetype.setSize(mimeTypeBytes.length);
		entryMimetype.setCompressedSize(mimeTypeBytes.length);
		final CRC32 crc = new CRC32();
		crc.update(mimeTypeBytes);
		entryMimetype.setCrc(crc.getValue());
		return entryMimetype;
	}

	/**
	 * This method creates a XAdES signature. When adding a new signature,  this one is appended to the already present signatures.
	 *
	 * @param asicParameters already present signatures
	 * @param signature      signature being created
	 * @param outZip         destination {@code ZipOutputStream}
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	private void buildXAdES(final ASiCParameters asicParameters, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {

		final String signatureZipEntryName = getSignatureFileName(asicParameters);
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		createZipEntry(outZip, entrySignature);
		// Creates the XAdES signature
		final Document xmlSignatureDoc = DSSXMLUtils.buildDOM(signature);
		storeXmlDom(outZip, xmlSignatureDoc);
	}

	private static void storeXmlDom(final OutputStream outZip, final Document xml) throws DSSException {

		try {
			final DOMSource xmlSource = new DOMSource(xml);
			final StreamResult outputTarget = new StreamResult(outZip);
			TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
		} catch (TransformerException e) {
			throw new DSSException(e);
		} catch (TransformerFactoryConfigurationError transformerFactoryConfigurationError) {
			transformerFactoryConfigurationError.printStackTrace();
		}
	}

	private boolean isAsics(final ASiCParameters asicParameters) {
		return SignatureForm.ASiC_S.equals(asicParameters.getContainerForm());
	}

	private boolean isAsice(final ASiCParameters asicParameters) {
		return SignatureForm.ASiC_E.equals(asicParameters.getContainerForm());
	}

	/**
	 * This method returns the specific service associated with the container: XAdES or CAdES.
	 *
	 * @param specificParameters {@code DocumentSignatureService}
	 * @return
	 */
	protected DocumentSignatureService getSpecificService(final SignatureParameters specificParameters) {

		final SignatureForm asicSignatureForm = specificParameters.aSiC().getUnderlyingForm();
		final DocumentSignatureService underlyingASiCService = specificParameters.getContext().getUnderlyingASiCService(certificateVerifier, asicSignatureForm);
		underlyingASiCService.setTspSource(tspSource);
		return underlyingASiCService;
	}

	static class AsicContext {

		private final SignatureForm containerForm;
		private final SignatureLevel containerLevel;

		private final SignatureForm subordinatedForm;
		private final SignatureLevel subordinatedLevel;
		private final SignaturePackaging subordinatedPackaging;

		private final DocumentValidator containerValidator; // null it the document to sign is not an ASiC container

		private DocumentValidator subordinatedValidator = null;

		private DSSDocument subordinatedSignature = null;
		private DSSDocument subordinatedToSignDocument = null;

		private String signatureFileName;

		/**
		 * This constructor initiates the following fields:<br>
		 * {@code containerForm} based on {@code SignatureForm}: ASiC container: S or E<br>
		 * {@code containerLevel} based on {@code SignatureLevel}: ASiC container: ASiC_S_BASELINE_B, ASiC_S_BASELINE_T...<br>
		 * {@code subordinatedForm} based on {@code SignatureForm} of the ASiC container: CAdES or XAdES<br>
		 * {@code subordinatedLevel} based on {@code SignatureLevel} of the ASiC container: CAdES_BASELINE_B, XAdES_BASELINE_T...<br>
		 */
		public AsicContext(final DSSDocument toSignDocument, final SignatureParameters parameters) {

			if (toSignDocument == null) {
				throw new DSSNullException(DSSDocument.class, "toSignDocument");
			}
			final ASiCParameters asicParameters = parameters.aSiC();
			final SignatureForm containerForm = asicParameters.getContainerForm();
			if (containerForm == null) {
				throw new DSSNullException(SignatureForm.class, "containerForm");
			}
			if (SignatureForm.ASiC_E != containerForm || SignatureForm.ASiC_S != containerForm) {
				throw new DSSException("The SignatureForm must be either ASiC_E or ASiC_S but was '" + containerForm + "'!");
			}
			final SignatureLevel containerLevel = parameters.getSignatureLevel();
			if (containerLevel == null) {
				throw new DSSNullException(SignatureLevel.class, "containerLevel");
			}
			final SignatureForm underlyingForm = asicParameters.getUnderlyingForm();
			if (underlyingForm == null) {
				throw new DSSNullException(SignatureForm.class, "subordinatedForm");
			}

			this.containerForm = containerForm;
			this.containerLevel = containerLevel;
			this.subordinatedForm = underlyingForm;

			this.subordinatedLevel = getUnderlyingLevel(containerLevel, containerForm);
			subordinatedPackaging = isCadesFrom() ? SignaturePackaging.DETACHED : SignaturePackaging.ENVELOPED;

			signatureFileName = getSignatureFileName(asicParameters.getSignatureFileName());

			containerValidator = getAsicValidator(toSignDocument);
			if (containerValidator != null) {

				subordinatedValidator = containerValidator.getSubordinatedValidator();
				subordinatedSignature = subordinatedValidator.getDocument();
				if (isAsice()) {

					if (isCadesFrom()) {

						subordinatedToSignDocument = createAsicManifest(parameters);
						//	???					underlyingParameters.setDetachedContent(null);
					} else { // XAdES form

						// A new asic:XAdESSignatures element is always created. It could be possible to add signatures to the existing one: the process to be set
						contextToSignDocument = createAsicXadesSignatures();
					}
				}
			}
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

		public SignaturePackaging getSubordinatedPackaging() {

			return subordinatedPackaging;
		}

		private static SignatureLevel getUnderlyingLevel(final SignatureLevel containerLevel, final SignatureForm containerForm) {

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

		private DSSDocument createAsicManifest(final SignatureParameters parameters) {

			final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			buildAsicManifest(parameters, outputStream);
			final DSSDocument contextToSignDocument = new InMemoryDocument(outputStream.toByteArray(), "AsicManifestXXX.xml", MimeType.XML);
			return contextToSignDocument;
		}

		private void buildAsicManifest(final SignatureParameters parameters, final OutputStream outputStream) {

			final Document documentDom = DSSXMLUtils.buildDOM();
			final Element asicManifestDom = documentDom.createElementNS(ASiCNamespaces.ASiC, "asic:ASiCManifest");
			documentDom.appendChild(asicManifestDom);

			final Element sigReferenceDom = DSSXMLUtils.addElement(documentDom, asicManifestDom, ASiCNamespaces.ASiC, "asic:SigReference");
			sigReferenceDom.setAttribute("URI", signatureFileName);
			final String signatureMimeType = getSignatureMimeType();
			sigReferenceDom.setAttribute("MimeType", signatureMimeType);

			DSSDocument currentDetachedDocument = parameters.getDetachedContent();
			do {

				final String detachedDocumentName = currentDetachedDocument.getName();
				final Element dataObjectReferenceDom = DSSXMLUtils.addElement(documentDom, sigReferenceDom, ASiCNamespaces.ASiC, "asic:DataObjectReference");
				dataObjectReferenceDom.setAttribute("URI", detachedDocumentName);

				final Element digestMethodDom = DSSXMLUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestMethod");
				final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
				digestMethodDom.setAttribute("Algorithm", digestAlgorithm.getXmlId());

				final Element digestValueDom = DSSXMLUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestValue");
				final byte[] digest = DSSUtils.digest(digestAlgorithm, currentDetachedDocument.getBytes());
				final String base64Encoded = DSSUtils.base64Encode(digest);
				final Text textNode = documentDom.createTextNode(base64Encoded);
				digestValueDom.appendChild(textNode);

				currentDetachedDocument = currentDetachedDocument.getNextDocument();
			} while (currentDetachedDocument != null);

			storeXmlDom(outputStream, documentDom);
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

		private String getSignatureMimeType() {

			if (isXadesFrom()) {

				return MimeType.PKCS7.getMimeTypeString();
			} else if (isCadesFrom()) {

				return MimeType.PKCS7.getMimeTypeString();
			} else {

				throw new DSSException("ASiC signature form must be XAdES or CAdES!");
			}
		}
	}
}
