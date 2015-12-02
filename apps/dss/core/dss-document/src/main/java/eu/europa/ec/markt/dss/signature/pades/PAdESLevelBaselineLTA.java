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

package eu.europa.ec.markt.dss.signature.pades;

import java.util.List;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.pades.PDFDocumentValidator;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
class PAdESLevelBaselineLTA implements SignatureExtension {

    private final PAdESLevelBaselineLT padesLevelBaselineLT;
	private final PAdESLevelBaselineT padesLevelBaselineT;
    private final CertificateVerifier certificateVerifier;

    public PAdESLevelBaselineLTA(TSPSource tspSource, CertificateVerifier certificateVerifier) {

        padesLevelBaselineLT = new PAdESLevelBaselineLT(tspSource, certificateVerifier);
		padesLevelBaselineT = new PAdESLevelBaselineT(tspSource);
        this.certificateVerifier = certificateVerifier;
    }

    @Override
    public DSSDocument extendSignatures(DSSDocument document, SignatureParameters params) throws DSSException {

        final PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
        pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
        final List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
        for (final AdvancedSignature signature : signatures) {

            if (!signature.isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_LT)) {

                document = padesLevelBaselineLT.extendSignatures(document, params);
                return document;
            }
        }
        return padesLevelBaselineT.extendSignatures(document, params);
    }
}
