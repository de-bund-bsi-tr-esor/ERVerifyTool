package de.bund.bsi.tr_esor.checktool.validation;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.Test;

import java.math.BigInteger;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.net.http.HttpClient;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;


public class TestOnlineOcspRequester {

    private static final String CERTIFICATE_FAKE_URL = "http://www.CertificateFakeUrl.com";

    private static final String OCSP_FAKE_URL = "http://www.OcspFakeUrl.com";

    private HttpClient client;

    private X509Certificate certificate;

    private X509Certificate issuerCertificate;

    private OnlineOcspRequester sut;

    @Test
    public void failMissingAIA() throws Exception
    {
        setupSut();

        var result = sut.retrieveOcspResponseFromIncludedUrl(certificate, issuerCertificate);

        assertThat(result).isNull();
    }

    @Test
    public void failNoOcspUrlsFound() throws Exception
    {
        setupSut();
        var aiaMock = mock(AccessDescription.class);
        var wrongIdentifier = new ASN1ObjectIdentifier("1.3.4.5.6.7");
        when(aiaMock.getAccessMethod()).thenReturn(wrongIdentifier);
        var aiaAccessDescription = new AccessDescription[]{aiaMock};
        doReturn(aiaAccessDescription).when(sut).extractAuthorityInformationAccess(certificate);

        var result = sut.retrieveOcspResponseFromIncludedUrl(certificate, issuerCertificate);

        assertThat(result).isNull();
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_ocsp);
    }

    @Test
    public void failOcspUrlNotParsed() throws Exception
    {
        setupSut();
        var aia = mock(AccessDescription.class);
        var generalName = mock(GeneralName.class);
        when(aia.getAccessMethod()).thenReturn(X509ObjectIdentifiers.id_ad_ocsp);
        when(aia.getAccessLocation()).thenReturn(generalName);
        var aiaAccessDescription = new AccessDescription[]{aia};
        doReturn(aiaAccessDescription).when(sut).extractAuthorityInformationAccess(certificate);
        doReturn(null).when(sut).parseGeneralName(generalName);

        var result = sut.retrieveOcspResponseFromIncludedUrl(certificate, issuerCertificate);

        assertThat(result).isNull();
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_ocsp);
        verify(sut).parseGeneralName(generalName);

    }

    @Test
    public void failNoIssuerCertificateLocationUrl() throws Exception
    {
        setupSut();
        var aiaAccessDescription = arrangeAia();
        doReturn(List.of()).when(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_caIssuers);

        var result = sut.retrieveOcspResponseFromIncludedUrl(certificate, null);

        assertThat(result).isNull();
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_ocsp);
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_caIssuers);
    }

    @Test
    public void failIssuerCertificateNotRetrieved() throws Exception
    {
        setupSut();
        var aiaAccessDescription = arrangeAia();
        doReturn(List.of(CERTIFICATE_FAKE_URL)).when(sut).analyseAuthorityInformationAccess(aiaAccessDescription,
                X509ObjectIdentifiers.id_ad_caIssuers);
        arrangeResponseOnHttpClientPost(null);

        var result = sut.retrieveOcspResponseFromIncludedUrl(certificate, null);

        assertThat(result).isNull();
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_ocsp);
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_caIssuers);
        verify(client, atLeast(1)).send(any(), any());
    }

    @Test
    public void failIssuerCertificateNotGeneratedFromResponse() throws Exception
    {
        setupSut();
        var httpResponse = mock(HttpResponse.class);
        var response = new byte[] {1, 2, 3, 4, 5};
        when(httpResponse.body()).thenReturn(response);
        var aiaAccessDescription = arrangeAia();
        arrangeResponseOnHttpClientPost(httpResponse);
        doReturn(List.of(CERTIFICATE_FAKE_URL)).when(sut).analyseAuthorityInformationAccess(aiaAccessDescription,
                X509ObjectIdentifiers.id_ad_caIssuers);
        doReturn(null).when(sut).generateCertificate(CERTIFICATE_FAKE_URL, response);

        var result = sut.retrieveOcspResponseFromIncludedUrl(certificate, null);

        assertThat(result).isNull();
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_ocsp);
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_caIssuers);
        verify(client, atLeast(1)).send(any(HttpRequest.class), eq(HttpResponse.BodyHandlers.ofByteArray()));
        verify(sut).generateCertificate(CERTIFICATE_FAKE_URL, response);
    }

    @Test
    public void successRetrieveOCSPResponse() throws Exception
    {
        setupSut();
        var ocspResp = setupOcspResponse();
        var request = new byte[0];
        var aiaAccessDescription = arrangeAia();
        arrangeExceptionOnHttpClientPost();
        doReturn(request).when(sut).buildOcspRequest(certificate, issuerCertificate);
        doReturn(ocspResp).when(sut).sendOcspRequest(OCSP_FAKE_URL, request);

        var result = sut.retrieveOcspResponseFromIncludedUrl(certificate, issuerCertificate);

        assertThat(result).isEqualTo(ocspResp);
        verify(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_ocsp);
        verify(sut).buildOcspRequest(certificate, issuerCertificate);
        verify(sut).sendOcspRequest(OCSP_FAKE_URL, request);
    }

    @Test
    public void interuptionExceptionOnHttpRequest() throws Exception
    {
        setupSut();
        var request = new byte[0];
        arrangeAia();
        arrangeExceptionOnHttpClientPost();
        doReturn(request).when(sut).buildOcspRequest(certificate, issuerCertificate);

        assertThatThrownBy(() -> sut.retrieveOcspResponseFromIncludedUrl(certificate, issuerCertificate)).isInstanceOf(OCSPException.class)
                .hasMessageContaining("Could not retrieve OCSP response for certificate " + certificate.getSerialNumber());
    }

    private OCSPResp setupOcspResponse()
    {
        var resp = mock(OCSPResp.class);
        var ocspRespnse = mock(OCSPResponse.class);
        var responseStatus = mock(OCSPResponseStatus.class);
        when(resp.toASN1Structure()).thenReturn(ocspRespnse);
        when(ocspRespnse.getResponseStatus()).thenReturn(responseStatus);
        when(responseStatus.getValue()).thenReturn(new BigInteger("0"));
        return resp;
    }

    private void setupSut()
    {
        certificate = mock(X509Certificate.class);
        issuerCertificate = mock(X509Certificate.class);
        client = mock(HttpClient.class);
        sut = new OnlineOcspRequester(client);
        sut = spy(sut);
    }

    private AccessDescription[] arrangeAia() throws Exception
    {
        var aia = mock(AccessDescription.class);
        var aiaAccessDescription = new AccessDescription[]{aia};
        doReturn(aiaAccessDescription).when(sut).extractAuthorityInformationAccess(certificate);
        doReturn(List.of(OCSP_FAKE_URL)).when(sut).analyseAuthorityInformationAccess(aiaAccessDescription, X509ObjectIdentifiers.id_ad_ocsp);
        return aiaAccessDescription;
    }

    private void arrangeExceptionOnHttpClientPost() throws Exception
    {
        doThrow(InterruptedException.class).when(client).send(any(HttpRequest.class), eq(HttpResponse.BodyHandlers.ofByteArray()));
    }

    private void arrangeResponseOnHttpClientPost(HttpResponse<byte[]> response) throws Exception
    {
        when(client.send(any(HttpRequest.class), eq(HttpResponse.BodyHandlers.ofByteArray()))).thenReturn(response);
    }

}
