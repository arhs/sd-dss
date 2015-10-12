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

package eu.europa.ec.markt.dss.validation102853.processes;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.CryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.IdentificationOfTheSignersCertificate;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.SignatureAcceptanceValidation;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.ValidationContextInitialisation;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.X509CertificateValidation;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

/**
 * This class creates the validation data (Basic Building Blocks) for all signatures.
 * <p/>
 * 5. Basic Building Blocks<br>
 * This clause presents basic building blocks that are usable in the signature validation process. Later clauses will
 * use these blocks to construct validation algorithms for specific scenarios.
 *
 * @author bielecro
 */
public class BasicBuildingBlocks extends BasicValidationProcess implements NodeName, NodeValue, AttributeName, Indication, ExceptionMessage {

	private static final Logger LOG = LoggerFactory.getLogger(BasicBuildingBlocks.class);

	private void isInitialised(final ProcessParameters params) {

		assertDiagnosticData(params.getDiagnosticData(), getClass());
	}

	/**
	 * This method lunches the construction process of basic building blocks.
	 *
	 * @param params validation process parameters
	 * @return {@code XmlDom} representing the detailed report of this process.
	 */
	public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

		isInitialised(params);
		LOG.debug(this.getClass().getSimpleName() + ": start.");

		params.setContextName(SIGNING_CERTIFICATE);

		final XmlNode basicBuildingBlocksXmlNode = mainNode.addChild(BASIC_BUILDING_BLOCKS);

		final List<XmlDom> signatureXmlDomList = params.getDiagnosticData().getElements("/DiagnosticData/Signature");
		for (final XmlDom signatureXmlDom : signatureXmlDomList) {

			final String signatureType = signatureXmlDom.getAttribute(TYPE);
			setSuitableValidationPolicy(params, signatureType);

			final Conclusion conclusion = new Conclusion();
			conclusion.setLocation(basicBuildingBlocksXmlNode.getLocation());

			params.setSignatureContext(signatureXmlDom);
			/**
			 * In this case signatureContext and contextElement are equal, but this is not the case for
			 * TimestampsBasicBuildingBlocks
			 */
			params.setContextElement(signatureXmlDom);

			/**
			 * 5. Basic Building Blocks
			 */

			final String signatureId = signatureXmlDom.getValue("./@Id");
			final XmlNode signatureXmlNode = basicBuildingBlocksXmlNode.addChild(SIGNATURE);
			signatureXmlNode.setAttribute(ID, signatureId);
			/**
			 * 5.1. Identification of the signer's certificate (ISC)
			 */
			final IdentificationOfTheSignersCertificate isc = new IdentificationOfTheSignersCertificate();
			final Conclusion iscConclusion = isc.run(params, signatureXmlNode, MAIN_SIGNATURE);
			if (!iscConclusion.isValid()) {

				signatureXmlNode.addChild(iscConclusion.toXmlNode());
				continue;
			}
			conclusion.addInfo(iscConclusion);
			conclusion.addWarnings(iscConclusion);

			/**
			 * 5.2. Validation Context Initialisation (VCI)
			 */
			final ValidationContextInitialisation vci = new ValidationContextInitialisation();
			final Conclusion vciConclusion = vci.run(params, signatureXmlNode);
			if (!vciConclusion.isValid()) {

				signatureXmlNode.addChild(vciConclusion.toXmlNode());
				continue;
			}
			conclusion.addInfo(vciConclusion);
			conclusion.addWarnings(vciConclusion);

			/**
			 * 5.4 Cryptographic Verification (CV)
			 * --> We check the CV before XCV to not repeat the same check with LTV if XCV is not conclusive.
			 */
			final CryptographicVerification cv = new CryptographicVerification();
			final Conclusion cvConclusion = cv.run(params, signatureXmlNode);
			if (!cvConclusion.isValid()) {

				signatureXmlNode.addChild(cvConclusion.toXmlNode());
				continue;
			}
			conclusion.addInfo(cvConclusion);
			conclusion.addWarnings(cvConclusion);

			/**
			 * 5.5 Signature Acceptance Validation (SAV)
			 * --> We check the SAV before XCV to not repeat the same check with LTV if XCV is not conclusive.
			 */
			final SignatureAcceptanceValidation sav = new SignatureAcceptanceValidation();
			final Conclusion savConclusion = sav.run(params, signatureXmlNode);
			if (!savConclusion.isValid()) {

				signatureXmlNode.addChild(savConclusion.toXmlNode());
				continue;
			}
			conclusion.addInfo(savConclusion);
			conclusion.addWarnings(savConclusion);

			/**
			 * 5.3 X.509 Certificate Validation (XCV)
			 */
			final X509CertificateValidation xcv = new X509CertificateValidation();
			final Conclusion xcvConclusion = xcv.run(params, signatureXmlNode, MAIN_SIGNATURE);
			if (!xcvConclusion.isValid()) {

				signatureXmlNode.addChild(xcvConclusion.toXmlNode());
				continue;
			}
			conclusion.addInfo(xcvConclusion);
			conclusion.addWarnings(xcvConclusion);

			conclusion.setIndication(VALID);
			final XmlNode conclusionXmlNode = conclusion.toXmlNode();
			signatureXmlNode.addChild(conclusionXmlNode);
		}
		final XmlDom BasicBuildingBlocksReportDom = basicBuildingBlocksXmlNode.toXmlDom();
		params.setBasicBuildingBlocksReport(BasicBuildingBlocksReportDom);
		return BasicBuildingBlocksReportDom;
	}
}
