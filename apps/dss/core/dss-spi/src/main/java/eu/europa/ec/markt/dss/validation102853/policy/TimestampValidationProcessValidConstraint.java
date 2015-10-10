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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents the timestamp validation process validity constraints.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class TimestampValidationProcessValidConstraint extends Constraint {

    private static final Logger LOG = LoggerFactory.getLogger(TimestampValidationProcessValidConstraint.class);
    private int validTimestampCount;
    private String subIndication1;
    private String subIndication2;

    /**
     * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
     * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
     *
     * @param level the constraint level string.
     */
    public TimestampValidationProcessValidConstraint(final String level) {

        super(level);
    }

    /**
     * This method carries out the validation of the constraint. This constraint has a constant {@code Level} FAIL.
     *
     * @return true if the constraint is met, false otherwise.
     */
    @Override
    public boolean check() {

        if (validTimestampCount < 1) {
            node.addChild(STATUS, KO);
            if (validTimestampCount == 0) {
                conclusion.setIndication(indication, subIndication1);
            } else {
                conclusion.setIndication(indication, subIndication2);
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

    public void setValidTimestampCount(final int validTimestampCount) {

        this.validTimestampCount = validTimestampCount;
    }

    public int getValidTimestampCount() {
        return validTimestampCount;
    }

    public void setSubIndication1(final String subIndication1) {
        this.subIndication1 = subIndication1;
    }

    public String getSubIndication1() {
        return subIndication1;
    }

    public void setSubIndication2(final String subIndication2) {
        this.subIndication2 = subIndication2;
    }

    public String getSubIndication2() {
        return subIndication2;
    }
}

