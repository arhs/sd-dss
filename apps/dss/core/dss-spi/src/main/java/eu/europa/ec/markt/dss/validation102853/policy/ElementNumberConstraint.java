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

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class ElementNumberConstraint extends Constraint {

	protected Integer expectedMinValue;
	protected Integer expectedMaxValue;

	/**
	 * This field represents the simple {@code int} value of the constraint
	 */
	protected int intValue;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code DSSException} is raised.
	 *
	 * @param level            the constraint level string.
	 * @param expectedMinValue
	 * @param expectedMaxValue
	 */
	public ElementNumberConstraint(final String level, final Integer expectedMinValue, final Integer expectedMaxValue) throws DSSException {

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
			addConstraintParameters();
			node.addChild(INFO, null, messageAttributes);
			return true;
		}
		boolean error = intValue < expectedMinValue || intValue > expectedMaxValue;
		if (error) {

			addConstraintParameters();
			if (warn()) {

				node.addChild(STATUS, WARN);
				conclusion.addWarning(failureMessageTag, messageAttributes);
				return true;
			}
			node.addChild(STATUS, KO);
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

	private void addConstraintParameters() {

		messageAttributes.put(EXPECTED_MIN_VALUE, String.valueOf(expectedMinValue));
		messageAttributes.put(EXPECTED_MAX_VALUE, String.valueOf(expectedMaxValue));
		messageAttributes.put(CONSTRAINT_VALUE, String.valueOf(intValue));
	}

	public int getExpectedMinValue() {
		return expectedMinValue;
	}

	public void setExpectedMinValue(int expectedMinValue) {
		this.expectedMinValue = expectedMinValue;
	}

	public int getExpectedMaxValue() {
		return expectedMaxValue;
	}

	public void setExpectedMaxValue(int expectedMaxValue) {
		this.expectedMaxValue = expectedMaxValue;
	}

	public int getIntValue() {
		return intValue;
	}

	public void setIntValue(int intValue) {
		this.intValue = intValue;
	}
}
