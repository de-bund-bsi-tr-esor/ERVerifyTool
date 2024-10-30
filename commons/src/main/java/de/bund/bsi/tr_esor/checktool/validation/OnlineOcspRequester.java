package de.bund.bsi.tr_esor.checktool.validation;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;

/**
 * This Class takes a Certificate and Retrieves OCSP Responses for it
 */
public class OnlineOcspRequester
{
    private static final Logger LOG = LoggerFactory.getLogger(OnlineOcspRequester.class);

    private static final int MULTIPLE_CHOICES_300 = 300;

    private final HttpClient client;

    /**
     * Initializes the needed http client for OCSP Requests
     */
    public OnlineOcspRequester()
    {
        var httpClientBuilder = HttpClient.newBuilder();
        httpClientBuilder.version(HttpClient.Version.HTTP_2);
        httpClientBuilder.connectTimeout(Duration.ofSeconds(20));
        this.client = httpClientBuilder.build();
    }

    OnlineOcspRequester(HttpClient client)
    {
        this.client = client;
    }

    /**
     * Retrieves OCSP response for given certificate.
     */
    public OCSPResp retrieveOcspResponseFromIncludedUrl(X509Certificate certificate) throws OCSPException {
        var serialNumber = certificate.getSerialNumber();
        try
        {
            var url = extractOcspUrlFromCertificate(certificate);
            if (url == null)
            {
                LOG.info("No URL for OCSP found for certificate {}", serialNumber);
                return null;
            }

            LOG.info("Requesting OCSP values from {} for certificate {}", url, serialNumber);
            var request = buildRequestOcspRequest(certificate);
            return sendOcspRequest(url, request);
        }
        catch (IOException | OperatorCreationException | OCSPException | CertificateException exception)
        {
            throw new OCSPException("Could not retrieve OCSP response for certificate " + serialNumber, exception);
        }
    }

    private String extractOcspUrlFromCertificate(X509Certificate cert) throws IOException
    {
        var extensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extensionValue == null)
        {
            return null;
        }

        var asn1Sequence = (ASN1Sequence)JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
        var objects = asn1Sequence.getObjects();

        while (objects.hasMoreElements())
        {
            var element = (ASN1Sequence)objects.nextElement();
            var location = (ASN1TaggedObject)element.getObjectAt(1);
            if (location.getTagNo() == GeneralName.uniformResourceIdentifier)
            {
                var uri = (ASN1OctetString) location.getObject();
                return new String(uri.getOctets(), StandardCharsets.UTF_8);
            }
        }
        return null;
    }


    /**
     * Builds an OCSP request from the serial number of the submitted user certificate and the submitted issuer certificate from which it
     * was signed.
     *
     * @param certificate the certificate to get oscp response
     * @return the OCSP request byte-array
     */
    private byte[] buildRequestOcspRequest(X509Certificate certificate)
            throws OCSPException, CertificateEncodingException, IOException, OperatorCreationException
    {
        var serialNumber = certificate.getSerialNumber();
        var certificateHolder = new X509CertificateHolder(certificate.getEncoded());
        var sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        var jcaDigestCalculatorProviderbuilder = new JcaDigestCalculatorProviderBuilder();
        var digestCalculatorProvider = jcaDigestCalculatorProviderbuilder.build();
        var digestCalculator = digestCalculatorProvider.get(new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId));
        var id = new CertificateID(digestCalculator, certificateHolder, serialNumber);

        var gen = new OCSPReqBuilder();
        gen.addRequest(id);

        var req = gen.build();
        return req.getEncoded();
    }

    /**
     * Sends the given OCSP <code>request</code> byte-array to the submitted OCSP responder.
     *
     * @param url the URL of the OCSP responder
     * @param ocspReq the OCSP request as a byte array
     * @return the OSCP response
     * @throws IOException, if sending the OCSP request failed or if the response could not be parsed as an OCSP response successfully
     */
    private OCSPResp sendOcspRequest(String url, byte[] ocspReq) throws IOException

    {
        var bytes = sendHTTPRequest(url, ocspReq);

        if (bytes == null)
        {
            LOG.info("Response received from {} was empty", url);
            return null;
        }

        LOG.info("OCSPRequest send to {} was successfully", url);
        return new OCSPResp(bytes);
    }

    private byte[] sendHTTPRequest(String url, byte[] request) throws IOException
    {
        try
        {
            var httpRequest = buildHttpRequest(url, request);
            var response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
            var status = response.statusCode();
            if (status >= MULTIPLE_CHOICES_300)
            {
                throw new IOException(String.format("Could not retrieve OCSP response for url %s. Got Status: %d and Reason %s.",
                        url,
                        status,
                        Arrays.toString(response.body())));
            }
            return response.body();
        }
        catch (InterruptedException exception)
        {
            Thread.currentThread().interrupt();
            var message =
                    String.format("Could not retrieve OCSP response for url %s. Got exception with message: %s", url, exception.getMessage());
            throw new IOException(message, exception);
        }
    }

    private HttpRequest buildHttpRequest(String url, byte[] ocspRequest)
    {
        var requestBuilder = HttpRequest.newBuilder();
        requestBuilder.uri(URI.create(url));
        requestBuilder.timeout(Duration.ofMinutes(1));
        requestBuilder.header("Accept", "application/ocsp-response");
        requestBuilder.header("Content-Type", "application/ocsp-request");
        requestBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(ocspRequest));
        return requestBuilder.build();
    }

}
