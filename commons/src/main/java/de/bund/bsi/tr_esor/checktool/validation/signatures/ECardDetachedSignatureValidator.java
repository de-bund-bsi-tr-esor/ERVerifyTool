/*- Copyright (c) 2018
 * Federal Office for Information Security (BSI),
 * Godesberger Allee 185-189,
 * 53175 Bonn, Germany,
 * phone: +49 228 99 9582-0,
 * fax: +49 228 99 9582-5400,
 * e-mail: bsi@bsi.bund.de
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.bund.bsi.tr_esor.checktool.validation.signatures;

import java.util.Collection;
import java.util.Map.Entry;

import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.InputDocuments;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss._1_0.core.schema.SignaturePtr;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignatureValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;

import de.bund.bsi.ecard.api._1.VerifyRequest;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Validator for signatures. It issues an eCard VerifyRequest to the configured eCard-compliant web service
 * and adds the returned VerificationReport to the context.
 *
 * @author TT, WS
 */
public class ECardDetachedSignatureValidator
  extends BaseECardSignatureValidator<SignatureObject, DetachedSignatureValidationContext>
{

  /**
   * Creates a signature verification request based on a detached signature. With encapsulated signatures, the
   * format of the request may differ.
   */
  @Override
  @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
  protected VerifyRequest createVerifyRequest(SignatureObject sig) throws JAXBException
  {
    VerifyRequest request = XmlHelper.FACTORY_ECARD.createVerifyRequest();
    request.setRequestID("id#" + System.currentTimeMillis());
    request.setOptionalInputs(createReturnVerificationReportOI());

    InputDocuments inp = XmlHelper.FACTORY_DSS.createInputDocuments();
    request.setInputDocuments(inp);
    for ( Entry<Reference, byte[]> entry : ctx.getProtectedDataByID().entrySet() )
    {
      DocumentType doc = createBase64Document(entry.getKey().relativize(ctx.getReference()),
                                              entry.getValue());
      inp.getDocumentOrTransformedDataOrDocumentHash().add(doc);
    }
    Reference credRef = ctx.getReference();
    DocumentType doc = createBase64Document(credRef.toString(), credRef.getSignatureValue());
    inp.getDocumentOrTransformedDataOrDocumentHash().add(doc);

    SignaturePtr sigPtr = XmlHelper.FACTORY_DSS.createSignaturePtr();
    sigPtr.setWhichDocument(doc);
    de.bund.bsi.ecard.api._1.SignatureObject target = XmlHelper.FACTORY_ECARD.createSignatureObject();
    target.setSignaturePtr(sigPtr);
    request.getSignatureObject().add(target);
    return request;
  }

  @Override
  protected boolean isRestrictedValidation(VerificationReportType verificationReport, SignatureObject toCheck)
  {
    if (ctx.isRestrictedValidation() && toCheck != null && toCheck.getSignature() != null)
    {
      // check if any SigMathOK in given VerificationReport is invalid - in this case the validation is
      // assumed restricted
      return verificationReport.getIndividualReport()
                               .stream()
                               .map(IndividualReportType::getDetails)
                               .map(AnyType::getAny)
                               .flatMap(Collection::stream)
                               .map(JAXBElement.class::cast)
                               .map(JAXBElement::getValue)
                               .filter(DetailedSignatureReportType.class::isInstance)
                               .map(DetailedSignatureReportType.class::cast)
                               .map(DetailedSignatureReportType::getSignatureOK)
                               .map(SignatureValidityType::getSigMathOK)
                               .anyMatch(sigMathOk -> ValidationResultMajor.INVALID.toString()
                                                                                   .equals(sigMathOk.getResultMajor()));
    }
    return false;
  }

  @Override
  protected String noSignatureFoundMessage()
  {
    return "No signature found in credential.";
  }

  @Override
  protected Class<DetachedSignatureValidationContext> getRequiredContextClass()
  {
    return DetachedSignatureValidationContext.class;
  }
}
