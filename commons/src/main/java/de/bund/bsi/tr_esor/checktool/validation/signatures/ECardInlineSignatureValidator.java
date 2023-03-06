/*- Copyright (c) 2019
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

import java.io.IOException;

import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.InputDocuments;
import oasis.names.tc.dss._1_0.core.schema.SignaturePtr;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBException;

import de.bund.bsi.ecard.api._1.VerifyRequest;
import de.bund.bsi.tr_esor.checktool.data.InlineSignedData;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Validator for data objects. It issues an eCard VerifyRequest to the configured eCard-compliant web service
 * and adds the returned VerificationReport to the context.
 *
 * @author PRE
 */
public class ECardInlineSignatureValidator
  extends BaseECardSignatureValidator<InlineSignedData, InlineSignatureValidationContext>
{

  /**
   * Creates a signature verification request based on a detached signature. With encapsulated signatures, the
   * format of the request may differ.
   */
  @Override
  protected VerifyRequest createVerifyRequest(InlineSignedData data) throws JAXBException, IOException
  {
    VerifyRequest request = XmlHelper.FACTORY_ECARD.createVerifyRequest();
    request.setRequestID("id#" + System.currentTimeMillis());
    request.setOptionalInputs(createReturnVerificationReportOI());

    InputDocuments inp = XmlHelper.FACTORY_DSS.createInputDocuments();
    request.setInputDocuments(inp);
    DocumentType doc = createBase64Document(ctx.getReference().toString(),
                                            ctx.getObjectToValidate().readBinaryData());
    inp.getDocumentOrTransformedDataOrDocumentHash().add(doc);

    SignaturePtr sigPtr = XmlHelper.FACTORY_DSS.createSignaturePtr();
    sigPtr.setWhichDocument(doc);
    de.bund.bsi.ecard.api._1.SignatureObject target = XmlHelper.FACTORY_ECARD.createSignatureObject();
    target.setSignaturePtr(sigPtr);
    request.getSignatureObject().add(target);
    return request;
  }

  @Override
  protected boolean isRestrictedValidation(VerificationReportType verificationReport,
                                           InlineSignedData toCheck)
  {
    return false;
  }

  @Override
  protected String noSignatureFoundMessage()
  {
    return "No inline signature found in data object. Detached signatures might be present.";
  }

  @Override
  protected Class<InlineSignatureValidationContext> getRequiredContextClass()
  {
    return InlineSignatureValidationContext.class;
  }
}
