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

package eu.europa.ec.markt.dss.validation102853.rules;

public interface AttributeName {

	String CATEGORY = "Category";
	String CERTIFIED_ROLES = "CertifiedRoles";
	String CONSTRAINT_KO_VALUE = "ConstraintKoValue";
	String CONSTRAINT_OK_VALUE = "ConstraintOkValue";
	String CONSTRAINT_VALUE = "ConstraintValue";
	String CONTEXT = "Context";
	String DATE = "Date";
	String EXPECTED_MAX_VALUE = "ExpectedMaxValue";
	String EXPECTED_MIN_VALUE = "ExpectedMinValue";
	String EXPECTED_VALUE = "ExpectedValue";
	String FIELD = "Field";
	String PRODUCTION_TIME = "ProductionTime";
	String ID = "Id";
	String LEVEL = "Level";
	String LOCATION = "Location";
	String MAX = "Max";
	String MAXIMUM_REVOCATION_FRESHNESS = "MaximumRevocationFreshness";
	String MIN = "Min";
	String NAME_ID = "NameId";
	String OBJECT_REFERENCE = "ObjectReference";
	String PARENT_ID = "ParentId";
	String REQUESTED_ROLES = "RequestedRoles";
	String REVOCATION_ISSUING_TIME = "RevocationIssuingTime";
	String REVOCATION_NEXT_UPDATE = "RevocationNextUpdate";
	String REVOCATION_REASON = "RevocationReason";
	String REVOCATION_TIME = "RevocationTime";
	String SIZE = "Size";
	String SUB_CONTEXT = "SubContext";
	String TIMESTAMP_TYPE = "Type";
	String TYPE = "Type";
	String URI = "Uri";
	String XPATH = "XPath";
}
