package eu.europa.ec.markt.dss.parameter;

import java.io.Serializable;

public class PAdESParameters implements Serializable {

	private String reason;
	private String contactInfo;
	private String location;

	private int signatureSize = 9472; // default value in PdfBox

	/**
	 * This attribute is used to create visible signature in PAdES form
	 */
	private SignatureImageParameters imageParameters;

	/**
	 * @return the reason
	 */
	public String getReason() {
		return reason;
	}

	/**
	 * @param reason the reason to set
	 */
	public void setReason(final String reason) {
		this.reason = reason;
	}

	/**
	 * @return the contactInfo
	 */
	public String getContactInfo() {
		return contactInfo;
	}

	/**
	 * @param contactInfo the contactInfo to set
	 */
	public void setContactInfo(final String contactInfo) {
		this.contactInfo = contactInfo;
	}

	public SignatureImageParameters getImageParameters() {
		return imageParameters;
	}

	public void setImageParameters(SignatureImageParameters imageParameters) {
		this.imageParameters = imageParameters;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public int getSignatureSize() {
		return signatureSize;
	}

	/**
	 * This setter allows to reserve more than the default size for a signature (9472bytes)
	 */
	public void setSignatureSize(int signatureSize) {
		this.signatureSize = signatureSize;
	}

}
