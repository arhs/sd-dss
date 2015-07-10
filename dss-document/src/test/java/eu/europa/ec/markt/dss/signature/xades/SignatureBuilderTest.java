package eu.europa.ec.markt.dss.signature.xades;

import static org.junit.Assert.*;

import org.junit.Test;

public class SignatureBuilderTest {
    @Test
    public void uriEncoding() {
        assertEquals("file.txt", 
                SignatureBuilder.uriEncode("file.txt"));
        assertEquals("dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt", 
                SignatureBuilder.uriEncode("dds_JÜRIÖÖ € žŠ päev.txt"));
    }
}
