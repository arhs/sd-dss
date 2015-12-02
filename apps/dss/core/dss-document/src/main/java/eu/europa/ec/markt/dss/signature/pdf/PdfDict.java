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

package eu.europa.ec.markt.dss.signature.pdf;

import java.io.IOException;
import java.util.Calendar;

/**
 * The usage of this interface permit the user to choose the underlying PDF
 * library use to created PDF signatures.
 *
 * @version $Revision: 1653 $ - $Date: 2013-02-01 11:48:52 +0100 (Fri, 01 Feb
 *          2013) $
 */
public interface PdfDict {

	PdfDict getAsDict(String name);

	PdfArray getAsArray(String name);

	boolean hasAName(String name);

	/**
	 * Check if the dictionary contains a name with a specific (PDF Name) value
	 *
	 * @param name
	 * @param value
	 * @return
	 */
	boolean hasANameWithValue(String name, String value);

	byte[] get(String name) throws IOException;

	String[] list();

	void add(String key, PdfArray array);

	void add(String key, PdfStreamArray array);

	void add(String key, PdfDict dict);

	void add(String key, Calendar cal);
}
