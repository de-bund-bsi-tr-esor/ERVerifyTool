package de.bund.bsi.tr_esor.checktool.entry;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;

import jakarta.xml.ws.Endpoint;

import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;


/**
 * Integration Test (needs running crypto server and verification endpoint) for the VerifyRequest defined by
 * TR-ESOR S.4
 */
@SuppressWarnings({"PMD.CommentRequired", "checkstyle:JavadocMethod"})
public class TestS4VerifyOnlyIT
{

  private static final String ENDPOINT_URL = "http://localhost:9988/ErVerifyTool/esor13/exec";

  private static final String MAJOR_INDETERMINED = ":ResultMajor>urn:oasis:names:tc:dss:1.0:detail:indetermined";

  private static final String MAJOR_INVALID = ":ResultMajor>urn:oasis:names:tc:dss:1.0:detail:invalid";

  private static final String MAJOR_VALID = ":ResultMajor>urn:oasis:names:tc:dss:1.0:detail:valid";

  private static final String PARAMETER_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError";

  private static final String VERIFICATION_REPORT_NAMESPACE = "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema";

  private static final String VERIFICATION_REPORT = "VerificationReport";



  private static final int STATUS_CODE_OK = 200;

  @BeforeClass
  public static void beforeClass() throws Exception
  {
    TestUtils.loadConfig("/config.xml");

    publishEndpoint(ENDPOINT_URL);
  }

  @Test
  public void verifiesXaipWithER() throws Exception
  {
    var response = response("src/test/resources/requests/verify_xaip_ok_ers.txt");

    assertThat(response.statusCode(), is(STATUS_CODE_OK));
    assertThat(response.body(), containsString(MAJOR_INDETERMINED));
    assertThat(response.body(), containsString(VERIFICATION_REPORT_NAMESPACE));
    assertThat(response.body(), containsString(VERIFICATION_REPORT));
    assertThat(response.body(), not(containsString(PARAMETER_ERROR)));
  }

  @Test
  public void verifiesLXaipWithER() throws Exception
  {
    var response = response("src/test/resources/requests/verify_lxaip_ok_ers.txt");

    assertThat(response.statusCode(), is(STATUS_CODE_OK));
    assertThat(response.body(), containsString(MAJOR_INDETERMINED));
    assertThat(response.body(), containsString(VERIFICATION_REPORT_NAMESPACE));
    assertThat(response.body(), containsString(VERIFICATION_REPORT));
    assertThat(response.body(), not(containsString(PARAMETER_ERROR)));
  }

  @Test
  public void verifiesLXaipWithCredAndER() throws Exception
  {
    var response = response("src/test/resources/requests/verify_lxaip_cred_ok_ers.txt");

    assertThat(response.statusCode(), is(STATUS_CODE_OK));
    assertThat(response.body(), containsString(MAJOR_VALID));
    assertThat(response.body(), containsString(VERIFICATION_REPORT_NAMESPACE));
    assertThat(response.body(),
               containsString("<SignedObjectIdentifier XPath=\"VerifyRequest/InputDocuments/Document[@id='g']/InlineXML/credentialSection/credential[@credentialID='ER_2.16.840.1.101.3.4.2.1_V001']/evidenceRecord/asn1EvidenceRecord\"/>"));
    assertThat(response.body(), containsString("<SignedObjectIdentifier FieldName=\"CT_V001\""));
    assertThat(response.body(), containsString("<SignedObjectIdentifier FieldName=\"MDO_V001\""));
    assertThat(response.body(), not(containsString(PARAMETER_ERROR)));
    assertThat(response.body(), not(containsString(MAJOR_INVALID)));
    assertThat(response.body(), not(containsString(MAJOR_INDETERMINED)));
  }

  @Test
  public void verifiesLXaipWithMetaInlineSig() throws Exception
  {
    var response = response("src/test/resources/requests/verify_lxaip_meta_sig_ok.txt");

    assertThat(response.statusCode(), is(STATUS_CODE_OK));
    assertThat(response.body(), containsString(MAJOR_VALID));
    assertThat(response.body(), containsString(VERIFICATION_REPORT_NAMESPACE));
    assertThat(response.body(), containsString("<SignedObjectIdentifier FieldName=\"MD_01\""));
    assertThat(response.body(), containsString("<SignedObjectIdentifier FieldName=\"DO_01\""));
    assertThat(response.body(), not(containsString(PARAMETER_ERROR)));
    assertThat(response.body(), not(containsString(MAJOR_INVALID)));
    assertThat(response.body(), not(containsString(MAJOR_INDETERMINED)));
  }

  @Test
  public void verifiesLXaipWithDataInlineSig() throws Exception
  {
    var response = response("src/test/resources/requests/verify_lxaip_data_sig_ok.txt");

    assertThat(response.statusCode(), is(STATUS_CODE_OK));
    assertThat(response.body(), containsString(MAJOR_VALID));
    assertThat(response.body(), containsString(VERIFICATION_REPORT_NAMESPACE));
    assertThat(response.body(), containsString("<SignedObjectIdentifier FieldName=\"MD_01\""));
    assertThat(response.body(), containsString("<SignedObjectIdentifier FieldName=\"DO_01\""));
    assertThat(response.body(), not(containsString(PARAMETER_ERROR)));
    assertThat(response.body(), not(containsString(MAJOR_INVALID)));
    assertThat(response.body(), not(containsString(MAJOR_INDETERMINED)));
  }

  @Test
  public void verifiesLXaipWithMetaAndER() throws Exception
  {
    var response = response("src/test/resources/requests/verify_lxaip_meta_ok_ers.txt");

    assertThat(response.statusCode(), is(STATUS_CODE_OK));
    assertThat(response.body(), containsString(MAJOR_VALID));
    assertThat(response.body(), containsString(VERIFICATION_REPORT_NAMESPACE));
    assertThat(response.body(), containsString("SignedObjectIdentifier FieldName=\"fileSize_V001\""));
    assertThat(response.body(), containsString("SignedObjectIdentifier FieldName=\"Hundename_V001\""));
    assertThat(response.body(),
               containsString("<SignedObjectIdentifier XPath=\"VerifyRequest/InputDocuments/Document[@id='g']/InlineXML/credentialSection/credential[@credentialID='ER_2.16.840.1.101.3.4.2.1_V001']/evidenceRecord/asn1EvidenceRecord\"/>"));
    assertThat(response.body(),
               containsString("SignedObjectIdentifier FieldName=\"HundesteuerAnmeldung_V001\""));
    assertThat(response.body(), not(containsString(PARAMETER_ERROR)));
    assertThat(response.body(), not(containsString(MAJOR_INVALID)));
    assertThat(response.body(), not(containsString(MAJOR_INDETERMINED)));
  }

  private HttpResponse<String> response(String requestFile) throws java.io.IOException, InterruptedException
  {
    var request = HttpRequest.newBuilder()
                             .uri(URI.create(ENDPOINT_URL))
                             .POST(HttpRequest.BodyPublishers.ofFile(Path.of(requestFile)))
                             .build();

    return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
  }

  @SuppressWarnings("SameParameterValue")
  private static void publishEndpoint(String address)
  {
    Endpoint.publish(address, new S4VerifyOnly());
  }
}
