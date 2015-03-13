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

package eu.europa.ec.markt.dss.validation102853.ocsp;

import org.bouncycastle.asn1.DEROctetString;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author Robert Bielecki
 */
public class NonceContainer {

	/**
	 * This variable is used to prevent the replay attack.
	 */
	DEROctetString nonce;

	public NonceContainer() {

		final long currentTimeNonce = System.currentTimeMillis();
		nonce = new DEROctetString(DSSUtils.toByteArray(currentTimeNonce));
	}
}
