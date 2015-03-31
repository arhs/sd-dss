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

import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;

/**
 * This class allows to create a customized reference.
 *
 * @author Robert Bielecki
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DSSReference {

	private String id;
	private String uri;
	private String type;

	// .. is an optional attribute which describes the data within the Object (independent of its encoding).
	private String objectMimeType;
	// ... may be used to provide a URI that identifies the method by which the object is encoded.
	// ... if the Object contains base64 encoded PNG, the Encoding may be specified as 'http://www.w3.org/2000/09/xmldsig#base64' and the MimeType as 'image/png'.
	private String objectEncoding;

	private boolean setObjectId = true;

	private DigestAlgorithm digestMethod;

	private DSSDocument contents;

	private List<DSSTransform> transforms;

	/**
	 * The default constructor
	 */
	public DSSReference() {
	}

	/**
	 * Copy constructor.
	 *
	 * @param reference {@code DSSReference} to copy
	 */
	public DSSReference(final DSSReference reference) {

		id = reference.id;
		uri = reference.uri;
		type = reference.type;
		objectMimeType = reference.objectMimeType;
		objectEncoding = reference.objectEncoding;
		setObjectId = reference.setObjectId;
		digestMethod = reference.digestMethod;
		contents = reference.contents;
		if (reference.transforms != null && reference.transforms.size() > 0) {

			transforms = new ArrayList<DSSTransform>();
			for (final DSSTransform transform : reference.transforms) {

				final DSSTransform dssTransform = new DSSTransform(transform);
				transforms.add(dssTransform);
			}
		}
	}

	public String getId() {
		return id;
	}

	public void setId(final String id) {
		this.id = id;
	}

	public String getUri() {
		return uri;
	}

	public void setUri(final String uri) {
		this.uri = uri;
	}

	public String getType() {
		return type;
	}

	public void setType(final String type) {
		this.type = type;
	}

	public String getObjectMimeType() {
		return objectMimeType;
	}

	public void setObjectMimeType(final String objectMimeType) {
		this.objectMimeType = objectMimeType;
	}

	public String getObjectEncoding() {
		return objectEncoding;
	}

	public void setObjectEncoding(String objectEncoding) {
		this.objectEncoding = objectEncoding;
	}

	public boolean hasSetObjectId() {
		return setObjectId;
	}

	public void setSetObjectId(final boolean setObjectId) {
		this.setObjectId = setObjectId;
	}

	public DigestAlgorithm getDigestMethodAlgorithm() {
		return digestMethod;
	}

	public void setDigestMethodAlgorithm(final DigestAlgorithm digestMethod) {
		this.digestMethod = digestMethod;
	}

	public List<DSSTransform> getTransforms() {
		return transforms;
	}

	public void setTransforms(final List<DSSTransform> transforms) {
		this.transforms = transforms;
	}

	public DSSDocument getContents() {
		return contents;
	}

	public void setContents(final DSSDocument contents) {
		this.contents = contents;
	}

	@Override
	public String toString() {
		return "DSSReference{" +
			  "id='" + id + '\'' +
			  ", uri='" + uri + '\'' +
			  ", type='" + type + '\'' +
			  ", objectMimeType='" + objectMimeType + '\'' +
			  ", objectEncoding='" + objectEncoding + '\'' +
			  ", setObjectId=" + setObjectId +
			  ", digestMethod='" + (digestMethod != null ? digestMethod.getName() : digestMethod) + '\'' +
			  ", contents=" + (contents != null ? contents.toString() : contents) +
			  ", transforms=" + transforms +
			  '}';
	}
}
