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
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.DocumentValidator;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCContainerValidator;

/**
 * Implementation of {@code DocumentSignatureService} for ASiC-S and -E containers. It allows the creation of containers based on XAdES or CAdES standard.
 *
 * @author Robert Bielecki
 */
public class ASiCService extends AbstractSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCService.class);

	private final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
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

		assertSigningDateInCertificateValidityRange(parameters);

		final AsicContext asicContext = new AsicContext(this, toSignDocument, parameters);

		final DocumentSignatureService subordinatedService = asicContext.getSubordinatedService();
		final DSSDocument subordinatedToSignDocument = asicContext.getSubordinatedToSignDocument();
		final SignatureParameters subordinatedParameters = asicContext.getSubordinatedParameters();
		return subordinatedService.getDataToSign(subordinatedToSignDocument, subordinatedParameters);
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

		final AsicContext asicContext = new AsicContext(this, toSignDocument, parameters);

		final DocumentSignatureService subordinatedService = asicContext.getSubordinatedService();
		final DSSDocument subordinatedToSignDocument = asicContext.getSubordinatedToSignDocument();
		final SignatureParameters subordinatedParameters = asicContext.getSubordinatedParameters();
		final DSSDocument subordinatedSignature = subordinatedService.signDocument(subordinatedToSignDocument, subordinatedParameters, signatureValue);

		final InMemoryDocument newContainer = buildASiCContainer(asicContext, subordinatedSignature);
		parameters.setDeterministicId(null);
		return newContainer;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		assertSignatureTokenConnectionNotNull(signingToken);
		final byte[] dataToSign = getDataToSign(toSignDocument, parameters);
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry privateKeyEntry = parameters.getPrivateKeyEntry();
		final byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKeyEntry);
		final DSSDocument dssDocument = signDocument(toSignDocument, parameters, signatureValue);
		return dssDocument;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final SignatureParameters parameters) throws DSSException {

		final AsicContext asicContext = new AsicContext(this, toExtendDocument, parameters);
		assertToExtentDocumentIsAsicContainer(asicContext);

		final DocumentSignatureService subordinatedService = asicContext.getSubordinatedService();
		final DSSDocument subordinatedSignature = asicContext.getSubordinatedSignature();
		final SignatureParameters subordinatedParameters = asicContext.getSubordinatedParameters();
		final DocumentValidator subordinatedValidator = asicContext.getSubordinatedValidator();
		final DSSDocument detachedContents = getDetachedContents(subordinatedValidator, parameters.getDetachedContent());
		subordinatedParameters.setDetachedContent(detachedContents);
		final DSSDocument signedDocument = subordinatedService.extendDocument(subordinatedSignature, subordinatedParameters);

		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		final ZipOutputStream zipOutputStream = new ZipOutputStream(output);
		final ZipInputStream zipInputStream = new ZipInputStream(toExtendDocument.openStream());
		ZipEntry entry;
		while ((entry = getNextZipEntry(zipInputStream)) != null) {

			final String name = entry.getName();
			final ZipEntry newEntry = new ZipEntry(name);
			if (ASiCContainerValidator.isMimetype(name)) {

				storeMimetype(asicContext, zipOutputStream);
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

	private void assertToExtentDocumentIsAsicContainer(AsicContext asicContext) {
		if (!asicContext.isExistingContainer()) {
			throw new DSSException("To extend document is not an existing ASiC container!");
		}
	}

	private void assertSignatureTokenConnectionNotNull(SignatureTokenConnection signingToken) {

		if (signingToken == null) {
			throw new DSSNullException(SignatureTokenConnection.class);
		}
	}

	private InMemoryDocument buildASiCContainer(final AsicContext asicContext, final DSSDocument subordinatedSignature) {

		final DSSDocument detachedContents = asicContext.getDetachedContents();
		final String toSignDocumentName = detachedContents.getName(); // The name of the first document to sign

		final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		final ZipOutputStream zipOutputStream = new ZipOutputStream(byteArrayOutputStream);
		if (asicContext.isAsice() && asicContext.isExistingContainer()) {
			copyZipContent(asicContext.getExistingContainer(), zipOutputStream);
		} else {

			storeZipComment(asicContext, zipOutputStream, toSignDocumentName);
			storeMimetype(asicContext, zipOutputStream);
		}
		storeSignedFiles(detachedContents, zipOutputStream);

		storesSignature(asicContext, subordinatedSignature, zipOutputStream);

		if (asicContext.isAsice() && asicContext.isCadesFrom()) {
			storeAsicManifest(asicContext, zipOutputStream);
		}
		DSSUtils.close(zipOutputStream);
		final InputStream inputStream = DSSUtils.toInputStream(byteArrayOutputStream.toByteArray());
		final InMemoryDocument asicContainer = createASiCContainer(asicContext, inputStream);
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

	private void storeAsicManifest(final AsicContext asicContext, final ZipOutputStream outZip) {

		final String signatureName = asicContext.getSignatureFileName();
		final int indexOfSignature = signatureName.indexOf("signature");
		String suffix = signatureName.substring(indexOfSignature + "signature".length());
		final int lastIndexOf = suffix.lastIndexOf(".");
		suffix = suffix.substring(0, lastIndexOf);
		final String asicManifestZipEntryName = META_INF + "ASiCManifest" + suffix + ".xml";
		final ZipEntry entrySignature = new ZipEntry(asicManifestZipEntryName);
		createZipEntry(outZip, entrySignature);

		buildAsicManifest(asicContext, outZip);
	}

	private static void createZipEntry(final ZipOutputStream outZip, final ZipEntry entrySignature) throws DSSException {

		try {
			outZip.putNextEntry(entrySignature);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private static InMemoryDocument createASiCContainer(final AsicContext asicContext, final InputStream containerInputStream) {

		final DSSDocument detachedContents = asicContext.getDetachedContents();
		final String toSignDocumentName = detachedContents.getName(); // The name of the first document to sign
		final String extension = asicContext.isAsics() ? ASICS_EXTENSION : ASICE_EXTENSION;
		final String name = toSignDocumentName != null ? toSignDocumentName + extension : null;
		final MimeType mimeType = asicContext.isAsics() ? MimeType.ASICS : MimeType.ASICE;
		return new InMemoryDocument(containerInputStream, name, mimeType);
	}

	private void storesSignature(final AsicContext asicContext, final DSSDocument signature, final ZipOutputStream outZip) {

		if (asicContext.isXadesFrom()) {
			buildXAdES(asicContext, signature, outZip);
		} else { // CAdES form
			buildCAdES(asicContext, signature, outZip);
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

	private void storeZipComment(final AsicContext asicContext, final ZipOutputStream outZip, final String toSignDocumentName) {

		final ASiCParameters asicParameters = asicContext.getSubordinatedParameters().asic();
		// TODO-Bob (02/03/2015):  Check if the toSignDocumentName is mandatory
		if (asicParameters.isZipComment() && DSSUtils.isNotEmpty(toSignDocumentName)) {

			outZip.setComment("mimetype=" + getMimeTypeBytes(asicContext));
		}
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

	private void buildCAdES(final AsicContext asicParameters, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {

		final String signatureZipEntryName = asicParameters.getSignatureFileName();
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

	private void storeMimetype(final AsicContext asicContext, final ZipOutputStream outZip) throws DSSException {

		final byte[] mimeTypeBytes = getMimeTypeBytes(asicContext).getBytes();
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

	private String getMimeTypeBytes(final AsicContext asicContext) {

		final ASiCParameters asicParameters = asicContext.getSubordinatedParameters().asic();
		final String asicParameterMimeType = asicParameters.getMimeType();
		String mimeTypeBytes;
		if (DSSUtils.isBlank(asicParameterMimeType)) {

			if (asicContext.isAsice()) {
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
	 * @param asicContext already present signatures
	 * @param signature   signature being created
	 * @param outZip      destination {@code ZipOutputStream}
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	private void buildXAdES(final AsicContext asicContext, final DSSDocument signature, final ZipOutputStream outZip) throws DSSException {

		final String signatureZipEntryName = asicContext.getSignatureFileName();
		final ZipEntry entrySignature = new ZipEntry(signatureZipEntryName);
		createZipEntry(outZip, entrySignature);
		// Creates the XAdES signature
		final Document xmlSignatureDoc = DSSXMLUtils.buildDOM(signature);
		DSSXMLUtils.transform(xmlSignatureDoc, outZip);
	}

	public static void buildAsicManifest(final AsicContext asicContext, final OutputStream outputStream) {

		final Document domDocument = DSSXMLUtils.buildDOM();
		final Element asicManifestDom = domDocument.createElementNS(ASiCNamespaces.ASiC, "asic:ASiCManifest");
		domDocument.appendChild(asicManifestDom);

		final Element sigReferenceDom = DSSXMLUtils.addElement(domDocument, asicManifestDom, ASiCNamespaces.ASiC, "asic:SigReference");
		sigReferenceDom.setAttribute("URI", asicContext.getSignatureFileName());
		sigReferenceDom.setAttribute("MimeType", asicContext.getSignatureMimeType());

		DSSDocument currentDetachedDocument = asicContext.getDetachedContents();
		do {

			final String detachedDocumentName = currentDetachedDocument.getName();
			final Element dataObjectReferenceDom = DSSXMLUtils.addElement(domDocument, sigReferenceDom, ASiCNamespaces.ASiC, "asic:DataObjectReference");
			dataObjectReferenceDom.setAttribute("URI", detachedDocumentName);

			final Element digestMethodDom = DSSXMLUtils.addElement(domDocument, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestMethod");
			final DigestAlgorithm digestAlgorithm = asicContext.getManifestDigestAlgorithm();
			digestMethodDom.setAttribute("Algorithm", digestAlgorithm.getXmlId());

			final Element digestValueDom = DSSXMLUtils.addElement(domDocument, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestValue");
			final byte[] digest = DSSUtils.digest(digestAlgorithm, currentDetachedDocument.getBytes());
			final String base64Encoded = DSSUtils.base64Encode(digest);
			final Text textNode = domDocument.createTextNode(base64Encoded);
			digestValueDom.appendChild(textNode);

			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);

		DSSXMLUtils.transform(domDocument, outputStream);
	}
}
