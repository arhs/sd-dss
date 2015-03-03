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

package eu.europa.ec.markt.dss.parameter;

import java.io.Serializable;

import eu.europa.ec.markt.dss.validation102853.SignatureForm;

/**
 * This class regroups the signature parameters related to the ASiC form.
 *
 * @author Robert Bielecki
 */
public class ASiCParameters implements Serializable {

	/**
	 * Indicates if the ZIP comment should be used to store the signed content mime-type.
	 */
	private boolean zipComment = false;

	/**
	 * Indicates the mime-type to be set within the mimetype file. If null the stored mime-type is that of the signed content.
	 */
	private String mimeType = null;

	/**
	 * The default signature form to use within the ASiC containers.
	 */
	private SignatureForm subordinatedForm = SignatureForm.XAdES;

	/**
	 * The form of the container -S or -E.
	 */
	SignatureForm containerForm;

	/**
	 * This property allows to provide a specific signature file name in the case of an ASiC-E container.
	 */
	private String signatureFileName;

	/**
	 * Default constructor
	 */
	public ASiCParameters() {
	}

	/**
	 * A copy constructor.
	 *
	 * @param source {@code ASiCParameters}
	 */
	public ASiCParameters(final ASiCParameters source) {

		zipComment = source.zipComment;
		mimeType = source.mimeType;
		subordinatedForm = source.subordinatedForm;
		containerForm = source.containerForm;
		signatureFileName = source.signatureFileName;
	}

	/**
	 * Indicates if the ZIP comment must include the mime-type.
	 *
	 * @return {@code boolean}
	 */
	public boolean isZipComment() {
		return zipComment;
	}

	/**
	 * This method allows to indicate if the zip comment will contain the mime type.
	 *
	 * @param zipComment
	 */
	public void setZipComment(final boolean zipComment) {
		this.zipComment = zipComment;
	}

	public String getMimeType() {
		return mimeType;
	}

	/**
	 * This method allows to set the mime-type within the mimetype file.
	 *
	 * @param mimeType the mimetype to  store
	 */
	public void setMimeType(final String mimeType) {
		this.mimeType = mimeType;
	}

	/**
	 * @deprecated since 4.3.2-SNAPSHOT, use {@link #getSubordinatedForm()}
	 */
	@Deprecated
	public SignatureForm getUnderlyingForm() {
		return subordinatedForm;
	}

	public SignatureForm getSubordinatedForm() {
		return subordinatedForm;
	}

	/**
	 * @deprecated since 4.3.2-SNAPSHOT, use {@link #setSubordinatedForm(eu.europa.ec.markt.dss.validation102853.SignatureForm)}
	 */
	@Deprecated
	public void setUnderlyingForm(final SignatureForm underlyingForm) {
		this.subordinatedForm = underlyingForm;
	}

	/**
	 * Sets the signature form associated with an ASiC container. Only two forms are acceptable: XAdES and CAdES.
	 *
	 * @param subordinatedForm signature form to associate with the ASiC container.
	 */
	public void setSubordinatedForm(final SignatureForm subordinatedForm) {
		this.subordinatedForm = subordinatedForm;
	}

	/**
	 * @return the {@code SignatureForm} of the ASiC container
	 */
	public SignatureForm getContainerForm() {
		return containerForm;
	}

	/**
	 * This method returns the name of the signature file to use only with ASiC-E container.
	 *
	 * @return signature file name
	 */
	public String getSignatureFileName() {
		return signatureFileName;
	}

	/**
	 * This method allows to set the signature file name to use with ASiC-E container.
	 *
	 * @param signatureFileName signature file name
	 */
	public void setSignatureFileName(final String signatureFileName) {
		this.signatureFileName = signatureFileName;
	}
}
