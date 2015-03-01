package eu.europa.ec.markt.dss.validation102853;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

public class SignatureValidationContextTest {
    @Test
    public void exceptionsFromValidationThreadpoolArePropagatedToCallers() {
        SignatureValidationContext c  = new FailingSignatureValidationContext(new RuntimeException("Exception from Task"));
        
        c.addCertificateTokenForVerification(new CertificateToken(TestCertificates.SIGN_CERT_EC, 0));
        
        try {
            c.validate();
            fail("Exception expected");
        } catch(Exception e) {
            assertEquals("Exception from Task", e.getCause().getCause().getMessage());
        }
    }
    
    public static class FailingSignatureValidationContext extends SignatureValidationContext {
        private RuntimeException exception;

        public FailingSignatureValidationContext(RuntimeException exception) {
            this.exception = exception;
        }

        @Override
        protected Task createTask(Token token) {
            return createAlwaysFailingTask(token);
        }

        protected Task createAlwaysFailingTask(Token token) {
            return new Task(token) {
                @Override
                public void run() {
                    throw exception;
                }
            };
        }
    };
    
    
}
