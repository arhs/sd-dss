/*
 * Copyright  1999-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package eu.europa.ec.markt.dss.validation102853.xades;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

/**
 * This class helps us home users to resolve http URIs without a network connection
 *
 * @author $Author$
 */
public class OfflineManifestResolver extends ResourceResolverSpi {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineManifestResolver.class);

	static {

		Init.init();
	}

	private final List<DSSDocument> documents;

	private String lastUri;

	private HashMap<DigestAlgorithm, HashMap<String, DSSDocument>> algorithms = new HashMap<DigestAlgorithm, HashMap<String, DSSDocument>>();

	private DigestAlgorithm currentAlgorithm;
	private String currentHexEncodedDigestValue;

	public OfflineManifestResolver(final List<DSSDocument> documents) {

		this.documents = documents;
	}

	@Override
	public boolean engineCanResolveURI(final ResourceResolverContext context) {

		//		final Attr uriAttr = context.attr;
		//		String documentUri = uriAttr.getNodeValue();
		//		documentUri = decodeUrl(documentUri);
		//		lastUri = documentUri;
		lastUri = null;

		HashMap<String, DSSDocument> dssDocumentHashMap = initialise();
		return dssDocumentHashMap.containsKey(currentHexEncodedDigestValue);
	}

	private HashMap<String, DSSDocument> initialise() {

		HashMap<String, DSSDocument> dssDocumentHashMap = algorithms.get(currentAlgorithm);
		if (dssDocumentHashMap == null) {

			dssDocumentHashMap = new HashMap<String, DSSDocument>(documents.size());
			for (final DSSDocument document : documents) {

				final byte[] digest = DSSUtils.digest(currentAlgorithm, document.getBytes());
				final String encodeHexString = DSSUtils.encodeHexString(digest);
				dssDocumentHashMap.put(encodeHexString, document);
			}
			algorithms.put(currentAlgorithm, dssDocumentHashMap);
		}
		return dssDocumentHashMap;
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {

		final Attr uriAttr = context.attr;
		final String baseUriString = context.baseUri;
		String documentUri = uriAttr.getNodeValue();

		HashMap<String, DSSDocument> dssDocumentHashMap = algorithms.get(currentAlgorithm);
		final DSSDocument dssDocument = dssDocumentHashMap.get(currentHexEncodedDigestValue);
		if (dssDocument != null) {

			lastUri = dssDocument.getAbsolutePath();

			InputStream inputStream = dssDocument.openStream();
			final byte[] bytes = DSSUtils.toByteArray(inputStream);
			inputStream = new ByteArrayInputStream(bytes);

			final XMLSignatureInput result = new XMLSignatureInput(inputStream);
			result.setSourceURI(documentUri);
			final MimeType mimeType = dssDocument.getMimeType();
			if (mimeType != null) {
				result.setMIMEType(mimeType.getMimeTypeString());
			}
			return result;
		} else {

			Object exArgs[] = {"The uriNodeValue " + documentUri + " is not configured for offline work"};
			throw new ResourceResolverException("generic.EmptyMessage", exArgs, documentUri, baseUriString);
		}
	}

	private String decodeUrl(String documentUri) {
		try {
			return URLDecoder.decode(documentUri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			LOG.error(e.getMessage(), e);
		}
		return documentUri;
	}

	public String getLastUri() {
		return lastUri;
	}

	public void setCurrentDigest(final MessageDigestAlgorithm messageDigestAlgorithm, final byte[] digestValue) {

		currentAlgorithm = DigestAlgorithm.forName(messageDigestAlgorithm.getAlgorithm().getAlgorithm());
		currentHexEncodedDigestValue = DSSUtils.encodeHexString(digestValue);
	}

	public boolean preVerify() {

		return false;
	}
}