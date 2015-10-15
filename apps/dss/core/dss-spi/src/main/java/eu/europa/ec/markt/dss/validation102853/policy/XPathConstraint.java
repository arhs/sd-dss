package eu.europa.ec.markt.dss.validation102853.policy;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class XPathConstraint extends Constraint {

	protected String xPath;

	protected String signatureId;

	/**
	 * @param level
	 * @param xPath
	 */
	public XPathConstraint(final String level, final String xPath) {

		super(level);
		this.xPath = xPath;
	}

	public void setSignatureId(String signatureId) {
		this.signatureId = signatureId;
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
		value = executeQuery(xPath);
		if (inform()) {

			node.addChild(STATUS, INFORMATION);
			node.addChild(INFO, null, messageAttributes).setAttribute(EXPECTED_VALUE, expectedValue).setAttribute(CONSTRAINT_VALUE, this.value);
			return true;
		}
		boolean error = value.isEmpty();
		if (!error) {

			if (!"*".equals(expectedValue)) {

				error = expectedValue != null && !expectedValue.equals(value);
			}
		}
		if (error) {

			if (warn()) {

				node.addChild(STATUS, WARN);
				node.addChild(WARNING, failureMessageTag, messageAttributes);
				if (DSSUtils.isNotBlank(expectedValue) && !TRUE.equals(expectedValue) && !FALSE.equals(expectedValue)) {
					messageAttributes.put(EXPECTED_VALUE, expectedValue);
					messageAttributes.put(CONSTRAINT_VALUE, value);
				}
				conclusion.addWarning(failureMessageTag, messageAttributes);
				return true;
			}
			node.addChild(STATUS, KO);
			if (DSSUtils.isNotBlank(expectedValue) && !TRUE.equals(expectedValue) && !FALSE.equals(expectedValue)) {
				messageAttributes.put(EXPECTED_VALUE, expectedValue);
				messageAttributes.put(CONSTRAINT_VALUE, value);
			}
			if (DSSUtils.isNotBlank(indication)) {
				conclusion.setIndication(indication, subIndication);
			}
			conclusion.addError(failureMessageTag, messageAttributes);
			return false;
		}
		addOkNode();
		return true;
	}

	/**
	 * @param query
	 * @return
	 */
	protected String executeQuery(final String query) {

		final String preparedQuery = prepareQuery(query);
		final boolean value = diagnosticData.getBooleanValue(preparedQuery);
		return String.valueOf(value);
	}

	/**
	 * @param query
	 * @return
	 */
	protected String prepareQuery(final String query) {

		String preparedQuery = query.replace("{$DiagnosticData}", "/DiagnosticData");
		preparedQuery = preparedQuery.replace("{$signatureId}", signatureId);
		return preparedQuery;
	}
}
