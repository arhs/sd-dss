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

package eu.europa.ec.markt.dss.signature.xades;

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.DSSTransform;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;

/**
 * This class handles the specifics of the enveloping XML signature
 *
 * @author Robert Bielecki
 */
class EnvelopingSignatureBuilder extends SignatureBuilder {

	/**
	 * The default constructor for EnvelopingSignatureBuilder. The enveloped signature uses by default the inclusive
	 * method of canonicalization.
	 *
	 * @param params              The set of parameters relating to the structure and process of the creation or extension of the
	 *                            electronic signature.
	 * @param origDoc             The original document to sign.
	 * @param certificateVerifier
	 */
	public EnvelopingSignatureBuilder(final SignatureParameters params, final DSSDocument origDoc, final CertificateVerifier certificateVerifier) {

		super(params, origDoc, certificateVerifier);
		setCanonicalizationMethods(params, CanonicalizationMethod.INCLUSIVE);
	}

	/**
	 * {@code inheritDoc}<br>
	 * By default the encapsulated, signed data is base 64 encoded.
	 */
	@Override
	protected List<DSSReference> createDefaultReferences() {

		final List<DSSReference> references = new ArrayList<DSSReference>();

		//<ds:Reference Id="signed-data-ref" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#signed-data-idfc5ff27ee49763d9ba88ba5bbc49f732">
		final DSSReference reference = new DSSReference();
		reference.setId("r-id-1");
		reference.setType(HTTP_WWW_W3_ORG_2000_09_XMLDSIG_OBJECT);
		reference.setUri("#o-id-1");
		reference.setContents(detachedDocument);
		reference.setDigestMethodAlgorithm(params.getDigestAlgorithm());

		final List<DSSTransform> transforms = new ArrayList<DSSTransform>();

		final DSSTransform transform = new DSSTransform();
		transform.setAlgorithm(CanonicalizationMethod.BASE64);

		transforms.add(transform);
		reference.setTransforms(transforms);
		references.add(reference);

		return references;
	}

	@Override
	protected DSSDocument transformReference(final DSSReference reference) {

		final DSSDocument contents = reference.getContents();
		if (MimeType.XML == contents.getMimeType()) { // In the case of an XML document

			if (!reference.hasSetObjectId()) { // when the reference does not point to the ds:Object, not the whole XML encapsulated data is signed

				final String uri = reference.getUri();
				if (DSSUtils.isNotEmpty(uri) && uri.charAt(0) == '#' && !isXPointer(uri)) { // and the URL is relative and not an XPointer

					final String id = uri.substring(1);
					// TODO-Bob (13/03/2015):  Add ID wen creating the node!
					DSSXMLUtils.recursiveIdBrowse(documentDom.getDocumentElement());
					final Element nodeToTransform = DSSXMLUtils.getElementById(documentDom, id); // The element to sign
					final List<DSSTransform> transforms = reference.getTransforms();
					if (DSSUtils.isEmpty(transforms)) { // if there is no transformation defined, the XML data is canonicalised

						byte[] transformedReferenceBytes = DSSXMLUtils.canonicalizeSubtree(CanonicalizationMethod.INCLUSIVE, nodeToTransform);
						return new InMemoryDocument(transformedReferenceBytes);
					}
				}
			}
		}
		return contents;
	}

	/**
	 * {@inheritDoc}
	 */
	protected void incorporateSpecificObjects() {

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			// <ds:Object>
			final Element objectDom = getObjectElement(reference);
			setObjectId(reference, objectDom);
			setObjectMimeType(reference, objectDom);
			setObjectEncoding(reference, objectDom);
		}
	}

	private Element getObjectElement(final DSSReference dssReference) {

		final DSSDocument dssDocument = dssReference.getContents();
		byte[] contents = dssDocument.getBytes();
		final List<DSSTransform> transforms = dssReference.getTransforms();
		if (transforms != null) {
			for (final DSSTransform transform : transforms) {
				if (CanonicalizationMethod.BASE64.equals(transform.getAlgorithm())) {
					contents = DSSUtils.base64BinaryEncode(contents);
					dssDocument.setMimeType(MimeType.TEXT);
				}
			}
		}
		if (dssDocument.getMimeType() == MimeType.XML) {

			final DocumentBuilderFactory documentBuilderFactory = DSSXMLUtils.getDocumentBuilderFactory(false);
			final Document document = DSSXMLUtils.buildDOM(documentBuilderFactory, contents);
			final Element objectDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLSignature.XMLNS, DS_OBJECT);

			final Node importedNode = documentDom.importNode(document.getDocumentElement(), true);
			objectDom.appendChild(importedNode);
			return objectDom;
		} else {

			final Element objectDom = DSSXMLUtils.addTextElement(documentDom, signatureDom, XMLSignature.XMLNS, DS_OBJECT, new String(contents));
			return objectDom;
		}
	}

	private void setObjectMimeType(final DSSReference reference, final Element objectDom) {

		final String objectMimeType = reference.getObjectMimeType();
		if (DSSUtils.isNotEmpty(objectMimeType)) {
			objectDom.setAttribute(MIME_TYPE, objectMimeType);
		}
	}

	private void setObjectEncoding(final DSSReference reference, final Element objectDom) {

		final String objectEncoding = reference.getObjectEncoding();
		if (DSSUtils.isNotEmpty(objectEncoding)) {
			objectDom.setAttribute(ENCODING, objectEncoding);
		}
	}

	private void setObjectId(final DSSReference reference, final Element objectDom) {

		final String uri = reference.getUri();
		if (DSSUtils.isNotEmpty(uri) && reference.hasSetObjectId()) {

			final String id = uri.substring(1);
			objectDom.setAttribute(ID, id);
		}
	}
}