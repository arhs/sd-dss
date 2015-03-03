/*
 * SD-DSS - Digital Signature Services
 *
 * Copyright (C) 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * Developed by: 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * This file is part of the "https://github.com/arhs/sd-dss" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "SD-DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature;

import java.io.Serializable;

import eu.europa.ec.markt.dss.signature.xades.SignatureBuilder;
import eu.europa.ec.markt.dss.signature.xades.XAdESLevelBaselineB;

/**
 * This class manages the internal variables used in the process of creating of a signature and which allows to
 * accelerate the generation.<br>
 * <p/>
 * TODO-Bob (01/03/2015):  This class must be derived to take also into account other formats then XAdES
 *
 * @author Robert Bielecki
 */
public class ProfileParameters implements Serializable {

	private XAdESLevelBaselineB profile;

	/**
	 * Returns the current Profile used to generate the signature or its extension
	 *
	 * @return
	 */
	public XAdESLevelBaselineB getProfile() {

		return profile;
	}

	/**
	 * Sets the current Profile used to generate the signature or its extension
	 *
	 * @return
	 */
	public void setProfile(XAdESLevelBaselineB profile) {

		this.profile = profile;
	}

	/*
	 * The builder used to create the signature structure. Currently used only for XAdES.
	 */
	private SignatureBuilder builder;

	public SignatureBuilder getBuilder() {

		return builder;
	}

	public void setBuilder(SignatureBuilder builder) {

		this.builder = builder;
	}

	/*
	 * The type of operation to perform.
	 */
	public static enum Operation {

		SIGNING, EXTENDING
	}

	/*
	 * Indicates the type of the operation to be done
	 */ Operation operationKind;

	public Operation getOperationKind() {

		return operationKind;
	}

	public void setOperationKind(Operation operationKind) {

		this.operationKind = operationKind;
	}
}
