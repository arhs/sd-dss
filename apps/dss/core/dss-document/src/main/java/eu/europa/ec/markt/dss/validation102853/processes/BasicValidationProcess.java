package eu.europa.ec.markt.dss.validation102853.processes;

import java.util.Date;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

import static eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage.EXCEPTION_TCOPPNTBI;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public abstract class BasicValidationProcess implements AttributeValue {


	protected static void assertDiagnosticData(final XmlDom diagnosticData, final Class<? extends BasicValidationProcess> aClass) {

		if (diagnosticData == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, aClass.getSimpleName(), "diagnosticData"));
		}
	}

	protected static void assertValidationPolicy(final ValidationPolicy validationPolicy, final Class<? extends BasicValidationProcess> aClass) {

		if (validationPolicy == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, aClass.getSimpleName(), "validationPolicy"));
		}
	}

	protected static void assertCurrentTime(final Date currentTime, final Class<? extends BasicValidationProcess> aClass) {

		if (currentTime == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, aClass.getSimpleName(), "currentTime"));
		}
	}

	protected static void assertContextElement(final XmlDom contextElement, final Class<? extends BasicValidationProcess> aClass) {

		if (contextElement == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, aClass.getSimpleName(), "contextElement"));
		}
	}

	protected void setSuitableValidationPolicy(final ProcessParameters params, final String signatureType) {

		final boolean countersignature = COUNTERSIGNATURE.equals(signatureType);
		params.setCurrentValidationPolicy(countersignature ? params.getCountersignatureValidationPolicy() : params.getValidationPolicy());
	}
}
