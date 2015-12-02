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

package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfStreamArray;
import eu.europa.ec.markt.dss.signature.pdf.model.ModelPdfArray;
import eu.europa.ec.markt.dss.signature.pdf.model.ModelPdfDict;

class PdfBoxDict implements PdfDict {

	COSDictionary wrapped;

	// Retain this reference ! PDDocument must not be garbage collected
	@SuppressWarnings("unused")
	private PDDocument document;

	public PdfBoxDict(COSDictionary wrapped, PDDocument document) {
		this.wrapped = wrapped;
		this.document = document;
	}


	public PdfBoxDict(ModelPdfDict dict) {
		wrapped = new COSDictionary();
		for (Map.Entry<String, Object> e : dict.getValues().entrySet()) {
			if (e.getValue() instanceof Calendar) {
				add(e.getKey(), (Calendar) e.getValue());
			} else if (e.getValue() instanceof ModelPdfDict) {
				add(e.getKey(), new PdfBoxDict((ModelPdfDict) e.getValue()));
			} else if (e.getValue() instanceof ModelPdfArray) {
				add(e.getKey(), new PdfBoxArray((ModelPdfArray) e.getValue()));
			} else if (e.getValue() instanceof String) {
				wrapped.setItem(e.getKey(), COSName.getPDFName((String) e.getValue()));
			} else {
				throw new IllegalArgumentException(e.getValue().getClass().getName());
			}
		}
	}

	public PdfBoxDict(String type) {
		wrapped = new COSDictionary();
		if (type != null) {
			wrapped.setItem("Type", COSName.getPDFName(type));
		}
	}

	@Override
	public PdfDict getAsDict(String name) {
		COSDictionary dict = (COSDictionary) wrapped.getDictionaryObject(name);
		if (dict == null) {
			return null;
		}
		return new PdfBoxDict(dict, document);
	}

	@Override
	public PdfArray getAsArray(String name) {
		COSArray array = (COSArray) wrapped.getDictionaryObject(name);
		if (array == null) {
			return null;
		}
		return new PdfBoxArray(array, document);
	}

	@Override
	public boolean hasAName(String name) {
		COSBase dictionaryObject = wrapped.getDictionaryObject(name);
		if (dictionaryObject == null) {
			return false;
		}
		return true;
	}

	@Override
	public boolean hasANameWithValue(String name, String value) {
		COSName pdfName = (COSName) wrapped.getDictionaryObject(name);
		if (pdfName == null) {
			return false;
		}
		return pdfName.getName().equals(value);
	}

	@Override
	public byte[] get(String name) throws IOException {
		COSBase val = wrapped.getDictionaryObject(name);
		if (val == null) {
			return null;
		}
		if (val instanceof COSString) {
			return ((COSString) val).getBytes();
		}
		if (val instanceof COSName) {
			return ((COSName) val).getName().getBytes();
		}
		throw new IOException(name + " was expected to be a COSString element but was " + val.getClass() + " : " + val);
	}

	@Override
	public String[] list() {
		final Set<COSName> cosNames = wrapped.keySet();
		List<String> result = new ArrayList<String>(cosNames.size());
		for (final COSName cosName : cosNames) {
			final String name = cosName.getName();
			result.add(name);
		}
		return result.toArray(new String[result.size()]);
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

	@Override
	public void add(String key, PdfArray array) {
		PdfBoxArray a = (PdfBoxArray) array;
		wrapped.setItem(key, a.wrapped);
		wrapped.setNeedToBeUpdate(true);
	}

	@Override
	public void add(String key, PdfStreamArray streamArray) {
		PdfBoxStreamArray a = (PdfBoxStreamArray) streamArray;
		wrapped.setItem(key, a.wrapped);
		wrapped.setNeedToBeUpdate(true);
	}

	@Override
	public void add(String key, PdfDict dict) {
		PdfBoxDict d = (PdfBoxDict) dict;
		wrapped.setItem(key, d.wrapped);
		wrapped.setNeedToBeUpdate(true);
	}

	@Override
	public void add(String key, Calendar cal) {
		wrapped.setDate(key, cal);
		wrapped.setNeedToBeUpdate(true);
	}

	public void setDirect(boolean direct) {
		wrapped.setDirect(direct);
	}

	COSDictionary getWrapped() {
		return wrapped;
	}

}
