/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2014 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2014 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.validation102853.scope;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.XAdESNamespaces;
import eu.europa.ec.markt.dss.validation102853.toolbox.XPointerResourceResolver;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

/**
 *
 */
public class XAdESSignatureScopeFinder implements SignatureScopeFinder<XAdESSignature> {

	private final List<String> transformationToIgnore = new ArrayList<String>();

	private final Map<String, String> presentableTransformationNames = new HashMap<String, String>();

	public XAdESSignatureScopeFinder() {

		// @see http://www.w3.org/TR/xmldsig-core/#sec-TransformAlg
		// those transformations don't change the content of the document
		transformationToIgnore.add("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
		transformationToIgnore.add("http://www.w3.org/2000/09/xmldsig#base64");
		transformationToIgnore.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
		transformationToIgnore.add("http://www.w3.org/2006/12/xml-c14n11#WithComments");
		transformationToIgnore.add("http://www.w3.org/2001/10/xml-exc-c14n#WithComments");


		// those transformations change the document and must be reported
		presentableTransformationNames.put("http://www.w3.org/2002/06/xmldsig-filter2", "XPath filtering");
		presentableTransformationNames.put("http://www.w3.org/TR/1999/REC-xpath-19991116", "XPath filtering");
		presentableTransformationNames.put("http://www.w3.org/TR/1999/REC-xslt-19991116", "XSLT Transform");

		presentableTransformationNames.put("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "Canonical XML 1.0 (omits comments)");
		presentableTransformationNames.put("http://www.w3.org/2006/12/xml-c14n11#", "Canonical XML 1.1 (omits comments)");
		presentableTransformationNames.put("http://www.w3.org/2001/10/xml-exc-c14n#", "Exclusive Canonical XML (omits comments)");
	}

	@Override
	public List<SignatureScope> findSignatureScope(final XAdESSignature xadesSignature) {

		final List<SignatureScope> result = new ArrayList<SignatureScope>();

		final Set<Element> unsignedObjects = new HashSet<Element>();
		unsignedObjects.addAll(xadesSignature.getSignatureObjects());
		final Set<Element> signedObjects = new HashSet<Element>();

		final List<Reference> signatureReferences = xadesSignature.getReferences();
		for (final Reference reference : signatureReferences) {

			final String referenceType = reference.getType();
			if (xadesSignature.getXPathQueryHolder().XADES_SIGNED_PROPERTIES.equals(referenceType)) {
				continue;
			}
			final String uri = reference.getURI();
			final List<String> transformations = getTransformationNames(reference);
			if (DSSUtils.isBlank(uri)) {
				// self contained document
				result.add(new XmlRootSignatureScope(transformations));
			} else if (uri.startsWith("#")) {

				// internal reference
				final String xmlIdOfReferencedElement = uri.substring(1);
				if (reference.typeIsReferenceToManifest()) {

					result.add(new ManifestSignatureScope(xmlIdOfReferencedElement, transformations));
					continue;
				}
				final boolean xPointerQuery = XPointerResourceResolver.isXPointerQuery(uri, true);
				if (xPointerQuery) {

					final String id = reference.getId();
					final XPointerSignatureScope xPointerSignatureScope = new XPointerSignatureScope(id, uri);
					result.add(xPointerSignatureScope);
					continue;
				}
				final String xPathString = XPathQueryHolder.XPATH_OBJECT + "[@Id='" + xmlIdOfReferencedElement + "']";
				final Element signatureElement = xadesSignature.getSignatureElement();
				Element signedElement = DSSXMLUtils.getElement(signatureElement, xPathString);
				if (signedElement != null) {
					if (unsignedObjects.remove(signedElement)) {
						signedObjects.add(signedElement);
						result.add(new XmlElementSignatureScope(xmlIdOfReferencedElement, transformations));
					}
				} else {
					signedElement = DSSXMLUtils.getElement(signatureElement.getOwnerDocument().getDocumentElement(), "//*" + "[@Id='" + xmlIdOfReferencedElement + "']");
					if (signedElement != null) {

						final String namespaceURI = signedElement.getNamespaceURI();
						if (namespaceURI == null || (!XAdESNamespaces.exists(namespaceURI) && !namespaceURI.equals(XMLSignature.XMLNS))) {
							signedObjects.add(signedElement);
							result.add(new XmlElementSignatureScope(xmlIdOfReferencedElement, transformations));
						}
					}
				}
			} else {
				// detached file
				if (reference.typeIsReferenceToManifest()) {

					result.add(new DetachedManifestSignatureScope(uri, transformations));
					continue;
				}
				result.add(new FullSignatureScope(uri));
			}
		}
		return result;
	}

	/**
	 * If there an error occurs during th transformation processing then
	 *
	 * @param reference
	 * @return
	 */
	private List<String> getTransformationNames(final Reference reference) {

		final List<String> algorithms = new ArrayList<String>();
		try {

			final Transforms transforms = reference.getTransforms();
			if (transforms == null) {
				return algorithms;
			}
			final int length = transforms.getLength();
			for (int ii = 0; ii < length; ii++) {

				try {
					final Transform transformation = transforms.item(ii);
					final String algorithm = transformation.getURI();
					if (transformationToIgnore.contains(algorithm)) {
						continue;
					}
					if (presentableTransformationNames.containsKey(algorithm)) {
						algorithms.add(presentableTransformationNames.get(algorithm));
					} else {
						algorithms.add(algorithm);
					}
				} catch (TransformationException e) {
					algorithms.add(e.getMessage());
				}
			}
		} catch (XMLSecurityException e) {
			algorithms.add(e.getMessage());
		}
		return algorithms;
	}
}
