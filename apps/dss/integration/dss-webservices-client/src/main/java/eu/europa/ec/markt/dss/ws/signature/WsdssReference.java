
package eu.europa.ec.markt.dss.ws.signature;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for wsdssReference complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="wsdssReference">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="contents" type="{http://ws.dss.markt.ec.europa.eu/}wsDocument" minOccurs="0"/>
 *         &lt;element name="digestMethodAlgorithm" type="{http://ws.dss.markt.ec.europa.eu/}digestAlgorithm" minOccurs="0"/>
 *         &lt;element name="id" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="transforms" type="{http://ws.dss.markt.ec.europa.eu/}dssTransform" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="type" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="uri" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "wsdssReference", propOrder = {
    "contents",
    "digestMethodAlgorithm",
    "id",
    "transforms",
    "type",
    "uri"
})
public class WsdssReference {

    protected WsDocument contents;
    protected DigestAlgorithm digestMethodAlgorithm;
    protected String id;
    @XmlElement(nillable = true)
    protected List<DssTransform> transforms;
    protected String type;
    protected String uri;

    /**
     * Gets the value of the contents property.
     * 
     * @return
     *     possible object is
     *     {@link WsDocument }
     *     
     */
    public WsDocument getContents() {
        return contents;
    }

    /**
     * Sets the value of the contents property.
     * 
     * @param value
     *     allowed object is
     *     {@link WsDocument }
     *     
     */
    public void setContents(WsDocument value) {
        this.contents = value;
    }

    /**
     * Gets the value of the digestMethodAlgorithm property.
     * 
     * @return
     *     possible object is
     *     {@link DigestAlgorithm }
     *     
     */
    public DigestAlgorithm getDigestMethodAlgorithm() {
        return digestMethodAlgorithm;
    }

    /**
     * Sets the value of the digestMethodAlgorithm property.
     * 
     * @param value
     *     allowed object is
     *     {@link DigestAlgorithm }
     *     
     */
    public void setDigestMethodAlgorithm(DigestAlgorithm value) {
        this.digestMethodAlgorithm = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setId(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the transforms property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the transforms property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getTransforms().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link DssTransform }
     * 
     * 
     */
    public List<DssTransform> getTransforms() {
        if (transforms == null) {
            transforms = new ArrayList<DssTransform>();
        }
        return this.transforms;
    }

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setType(String value) {
        this.type = value;
    }

    /**
     * Gets the value of the uri property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUri() {
        return uri;
    }

    /**
     * Sets the value of the uri property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUri(String value) {
        this.uri = value;
    }

}
