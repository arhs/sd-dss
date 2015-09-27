package eu.europa.ec.markt.dss.validation102853.processes;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public abstract class BasicValidationProcess {


	protected static void assertDiagnosticData(final XmlDom diagnosticData, final Class<? extends BasicValidationProcess> aClass) {

		if (diagnosticData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, aClass.getSimpleName(), "diagnosticData"));
		}
	}

	protected void assertValidationPolicy(final ValidationPolicy validationPolicy, final Class<? extends BasicValidationProcess> aClass) {

		if (validationPolicy == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, aClass.getSimpleName(), "validationPolicy"));
		}
	}
}
