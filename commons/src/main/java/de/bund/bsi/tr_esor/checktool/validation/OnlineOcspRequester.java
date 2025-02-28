package de.bund.bsi.tr_esor.checktool.validation;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
            var accessdescription = extractAuthorityInformationAccess(certificate);
            if (accessdescription == null)
            {
                return null;
            }
            var ocspUrlS = analyseAuthorityInformationAccess(accessdescription, X509ObjectIdentifiers.id_ad_ocsp);
            if (ocspUrlS.isEmpty())
            {
                LOG.info("No URL for OCSP found for certificate {}", serialNumber);
                return null;
            }
            var issuerCert = extractIssuerCertificate(accessdescription);
            for (var url : ocspUrlS)
            {
                LOG.info("Requesting OCSP values from {} for certificate {}", url, serialNumber);
                var request = buildOcspRequest(certificate, issuerCert);
                var resp = sendOcspRequest(url, request);
                if (resp != null)
                {
                    if (resp.toASN1Structure().getResponseStatus().getValue().intValue() == OCSPResponseStatus.SUCCESSFUL)
                    {
                        return resp;
                    }
                }
            }
            return null;
        }
        catch (IOException | OperatorCreationException | OCSPException | CertificateException exception)
        {
            throw new OCSPException("Could not retrieve OCSP response for certificate " + serialNumber, exception);
        }
    }

    private X509Certificate extractIssuerCertificate(AccessDescription[] accessdescription)
    {
        var issuerUrls = analyseAuthorityInformationAccess(accessdescription, X509ObjectIdentifiers.id_ad_caIssuers);
        if (issuerUrls.isEmpty())
        {
            return null;
        }

        for (var url : issuerUrls)
        {
            try
            {
                var httpRequest = buildBaseHttpRequest(url).build();
                var httpResponse = sendHTTPRequest(url, httpRequest);

                if (httpResponse == null)
                {
                    LOG.info("Response received from {} was empty", url);
                    continue;
                }

                try (var byteArrayInputStream = new ByteArrayInputStream(httpResponse))
                {
                    var issuerCertificate = (X509Certificate) CertificateFactory
                            .getInstance("X.509").generateCertificate(byteArrayInputStream);
                    if (issuerCertificate != null)
                    {
                        return issuerCertificate;
                    }
                }
            }
            catch (IllegalArgumentException | IOException | CertificateException e)
            {
                LOG.info("Could not build httpRequest with URL: {}", url);
            }
        }
        return null;
    }

    /**
     * Extracts the AuthorityInformationAccess Extension from a Provided Certificate
     */
    private AccessDescription[] extractAuthorityInformationAccess(X509Certificate cert) throws IOException {
        var extensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extensionValue == null)
        {
            return null;
        }

        var asn1Sequence = (ASN1Sequence)JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
        if (asn1Sequence == null || asn1Sequence.size() == 0)
        {
            return null;
        }

        var authorityInformationAccess = AuthorityInformationAccess.getInstance(asn1Sequence);
        var accessdescription = authorityInformationAccess.getAccessDescriptions();
        return accessdescription;
    }

    /**
     * Obtains Information out of a provided AuthorityInformationExtension. This Methode is needed to Obtain Information to the Location of
     * the IssuerCertificate and the OCSPResponderUrl
     */
    private List<String> analyseAuthorityInformationAccess(AccessDescription[] accessdescription, ASN1ObjectIdentifier identifier)
    {
        var foundUrls = new ArrayList<String>();
        for (var desc : accessdescription)
        {
            if (identifier.equals(desc.getAccessMethod()))
            {
                var generalName = desc.getAccessLocation();
                var location = parseGeneralName(generalName);
                if (location != null)
                {
                    foundUrls.add(location);
                }
            }
        }
        return foundUrls;
    }

    private String parseGeneralName(GeneralName generalName)
    {
        if (GeneralName.uniformResourceIdentifier == generalName.getTagNo())
        {
            var asn1TaggedObject = (DERTaggedObject) generalName.toASN1Primitive();
            var url = (DERIA5String) asn1TaggedObject.getObject();
            return new String(url.getOctets(), StandardCharsets.UTF_8);
        }
        return null;
    }

    /**
     * Builds an OCSP request from the serial number of the submitted user certificate and the issuer certificate derived from the user certificate.
     * If no issuer certificate was retrieved the user certificate is used instead
     */
    private byte[] buildOcspRequest(X509Certificate certificate, X509Certificate issuerCertificate)
            throws OCSPException, CertificateEncodingException, IOException, OperatorCreationException
    {
        var serialNumber = certificate.getSerialNumber();
        var certificateHolder = new X509CertificateHolder(certificate.getEncoded());
        if (issuerCertificate != null)
        {
            certificateHolder = new X509CertificateHolder(issuerCertificate.getEncoded());
        }
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
    private OCSPResp sendOcspRequest(String url, byte[] ocspReq) throws IOException, IllegalArgumentException

    {
        var httpRequest = buildHttpOCSPRequest(url, ocspReq).build();
        var httpResponse = sendHTTPRequest(url, httpRequest);

        if (httpResponse == null)
        {
            LOG.info("Response received from {} was empty", url);
            return null;
        }

        LOG.info("OCSPRequest send to {} was successfully", url);
        return new OCSPResp(httpResponse);
    }

    private byte[] sendHTTPRequest(String url, HttpRequest httpRequest) throws IOException
    {
        try
        {
            var response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
            var status = response.statusCode();
            if (status >= MULTIPLE_CHOICES_300)
            {
                throw new IOException(String.format("Could not execute Request for url %s. Got Status: %d and Reason %s.",
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
                    String.format("Could not execute request for url %s. Got exception with message: %s", url, exception.getMessage());
            throw new IOException(message, exception);
        }
    }

    private HttpRequest.Builder buildHttpOCSPRequest(String url, byte[] ocspRequest) throws IllegalArgumentException
    {
        var requestBuilder = buildBaseHttpRequest(url);
        requestBuilder.header("Accept", "application/ocsp-response");
        requestBuilder.header("Content-Type", "application/ocsp-request");
        requestBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(ocspRequest));
        return requestBuilder;
    }

    private HttpRequest.Builder buildBaseHttpRequest(String url) throws IllegalArgumentException
    {
        var requestBuilder = HttpRequest.newBuilder();
        requestBuilder.uri(URI.create(url));
        requestBuilder.timeout(Duration.ofMinutes(1));
        return requestBuilder;
    }

}
