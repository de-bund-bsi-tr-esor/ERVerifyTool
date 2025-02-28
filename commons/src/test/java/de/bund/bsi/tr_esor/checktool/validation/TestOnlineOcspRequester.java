package de.bund.bsi.tr_esor.checktool.validation;

import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.net.http.HttpClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class TestOnlineOcspRequester {

    private final String NO_AIA_ISSUER_URL = "no_AIA_issuer_Url.crt";

    private final String INVALID_AIA_ISSUER_URL = "invalid_AIA_issuer_Url.crt";

    private final String VALID_AIA_ISSUER_URL = "invalid_AIA_issuer_Url.crt";

    private HttpClient client;

    private OnlineOcspRequester sut;


    @Before
    public void setup()
    {
        client = mock(HttpClient.class);
        sut = new OnlineOcspRequester(client);
    }

    @Test
    public void ioExceptionOnHttpRequest() throws Exception
    {
        var certificate = loadCertificate(VALID_AIA_ISSUER_URL);
        arrangeExceptionOnHttpClientPost();

        assertThatThrownBy(() -> sut.retrieveOcspResponseFromIncludedUrl(certificate)).isInstanceOf(OCSPException.class)
                .hasMessageContaining("Could not retrieve OCSP response for certificate " + certificate.getSerialNumber());
    }

    @Test
    public void badRequestOnHttpRequest() throws Exception
    {
        var certificate = loadCertificate(VALID_AIA_ISSUER_URL);
        var response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(400);
        arrangeResponseOnHttpClientPost(response);

        assertThatThrownBy(() -> sut.retrieveOcspResponseFromIncludedUrl(certificate)).isInstanceOf(OCSPException.class)
                .hasMessageContaining("Could not retrieve OCSP response for certificate " + certificate.getSerialNumber());
    }

    @Test
    public void noContentInHttpResponse() throws Exception
    {
        var certificate = loadCertificate(VALID_AIA_ISSUER_URL);
        var response = createResponseWithoutData();
        arrangeResponseOnHttpClientPost(response);

        var result = sut.retrieveOcspResponseFromIncludedUrl(certificate);

        assertThat(result).isNull();
    }

    @Test
    public void successNoAiaIssuerUrl() throws Exception
    {
        var certificate = loadCertificate(NO_AIA_ISSUER_URL);
        var sutWithRealClient = new OnlineOcspRequester();

        var result = sutWithRealClient.retrieveOcspResponseFromIncludedUrl(certificate);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(OCSPResponseStatus.SUCCESSFUL);
        assertThat(result.getResponseObject()).isNotNull();
    }

    @Test
    public void successInValidAiaIssuerUrl() throws Exception
    {
        var certificate = loadCertificate(INVALID_AIA_ISSUER_URL);
        var sutWithRealClient = new OnlineOcspRequester();

        var result = sutWithRealClient.retrieveOcspResponseFromIncludedUrl(certificate);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(OCSPResponseStatus.SUCCESSFUL);
        assertThat(result.getResponseObject()).isNotNull();
    }

    @Test
    public void successValidAiaIssuerUrl() throws Exception
    {
        var certificate = loadCertificate(VALID_AIA_ISSUER_URL);
        var sutWithRealClient = new OnlineOcspRequester();

        var result = sutWithRealClient.retrieveOcspResponseFromIncludedUrl(certificate);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(OCSPResponseStatus.SUCCESSFUL);
        assertThat(result.getResponseObject()).isNotNull();
    }

    private static X509Certificate loadCertificate(String certificateName) throws Exception
    {
        try (var inputStream = TestOnlineOcspRequester.class.getClassLoader().getResourceAsStream("timeStampTestCertificates/" + certificateName))
        {
            var factory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            return (X509Certificate)factory.generateCertificate(inputStream);
        }
    }

    private static HttpResponse<byte[]> createResponseWithoutData()
    {
        var response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        return response;
    }

    private void arrangeExceptionOnHttpClientPost() throws Exception
    {
        doThrow(IOException.class).when(client).send(any(HttpRequest.class), eq(HttpResponse.BodyHandlers.ofByteArray()));
    }

    private void arrangeResponseOnHttpClientPost(HttpResponse<byte[]> response) throws Exception
    {
        when(client.send(any(HttpRequest.class), eq(HttpResponse.BodyHandlers.ofByteArray()))).thenReturn(response);
    }

}
