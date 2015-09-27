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

package eu.europa.ec.markt.dss.validation102853.policy;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class OkKoElementNumberConstraint extends Constraint {

	protected Integer expectedMinValue;
	protected Integer expectedMaxValue;

	/**
	 * This field represents the number of Ok elements
	 */
	protected int okNumber;
	/**
	 * This field represents the number of Ko elements
	 */
	protected int koNumber;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code DSSException} is raised.
	 *
	 * @param level            the constraint level string.
	 * @param expectedMinValue
	 * @param expectedMaxValue
	 */
	public OkKoElementNumberConstraint(final String level, final Integer expectedMinValue, final Integer expectedMaxValue) throws DSSException {

		super(level);
		this.expectedMinValue = expectedMinValue;
		this.expectedMaxValue = expectedMaxValue;
	}

	/**
	 * This method carry out the validation of the constraint.
	 *
	 * @return true if the constraint is met, false otherwise.
	 */
	public boolean check() {

		if (ignore()) {

			node.addChild(STATUS, IGNORED);
			return true;
		}
		if (inform()) {

			node.addChild(STATUS, INFORMATION);
			final XmlNode xmlNode = node.addChild(INFO, null, messageAttributes);
			addDetails(xmlNode);
			return true;
		}
		boolean error = true;
		if (okNumber > 0) {

			if (expectedMinValue == null && expectedMaxValue == null) { // OK == KO

				error = okNumber != koNumber;
			} else if (expectedMinValue != null && expectedMaxValue == null) { // expectedMinValue OR MORE

				error = okNumber < expectedMinValue;
			}
		}
		if (error) {

			if (warn()) {

				node.addChild(STATUS, WARN);
				final XmlNode xmlNode = node.addChild(WARNING, failureMessageTag, messageAttributes);
				addDetails(xmlNode);
				conclusion.addWarning(failureMessageTag, messageAttributes);
				return true;
			}
			node.addChild(STATUS, KO);
			final XmlNode xmlNode = node.addChild(ERROR);
			addDetails(xmlNode);
			if (DSSUtils.isNotBlank(indication)) {
				conclusion.setIndication(indication, subIndication);
			}
			conclusion.addError(failureMessageTag, messageAttributes);
			return false;
		}
		node.addChild(STATUS, OK);
		if (!messageAttributes.isEmpty()) {
			node.addChild(INFO, null, messageAttributes);
		}
		return true;
	}

	private void addDetails(XmlNode xmlNode) {
		xmlNode.setAttribute(EXPECTED_MIN_VALUE, String.valueOf(expectedMinValue)).setAttribute(EXPECTED_MAX_VALUE, String.valueOf(expectedMaxValue))
			  .setAttribute(CONSTRAINT_OK_VALUE, String.valueOf(okNumber)).setAttribute(CONSTRAINT_KO_VALUE, String.valueOf(koNumber));
	}

	public Integer getExpectedMinValue() {
		return expectedMinValue;
	}

	public void setExpectedMinValue(Integer expectedMinValue) {
		this.expectedMinValue = expectedMinValue;
	}

	public Integer getExpectedMaxValue() {
		return expectedMaxValue;
	}

	public void setExpectedMaxValue(Integer expectedMaxValue) {
		this.expectedMaxValue = expectedMaxValue;
	}

	public int getOkNumber() {
		return okNumber;
	}

	public void setOkNumber(int okNumber) {
		this.okNumber = okNumber;
	}

	public int getKoNumber() {
		return koNumber;
	}

	public void setKoNumber(int koNumber) {
		this.koNumber = koNumber;
	}
}
