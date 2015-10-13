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

package eu.europa.ec.markt.dss.validation102853.bean;

import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * This class represents the commitment type indication identifiers extracted from the signature.
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CommitmentType {

	private String identifier;
	private String description;

	private List<ObjectReference> objectReferenceList = null;
	private boolean allSignedDataObjects;

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(final String identifier) {
		this.identifier = identifier;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(final String description) {
		this.description = description;
	}

	public void addObjectReference(final String reference, final boolean exists) {

		if (DSSUtils.isNotBlank(reference)) {
			if (objectReferenceList == null) {
				objectReferenceList = new ArrayList<ObjectReference>();
			}
			objectReferenceList.add(new ObjectReference(reference, exists));
		}
	}

	public List<ObjectReference> getObjectReferenceList() {
		return objectReferenceList;
	}

	public boolean isAllSignedDataObjects() {
		return allSignedDataObjects;
	}

	public void setAllSignedDataObjects(final boolean allSignedDataObjects) {
		this.allSignedDataObjects = allSignedDataObjects;
	}

	public class ObjectReference {
		String reference;
		boolean exists;

		public ObjectReference(final String reference, final boolean exists) {
			this.reference = reference;
			this.exists = exists;
		}

		public String getReference() {
			return reference;
		}

		public boolean isExists() {
			return exists;
		}
	}
}
