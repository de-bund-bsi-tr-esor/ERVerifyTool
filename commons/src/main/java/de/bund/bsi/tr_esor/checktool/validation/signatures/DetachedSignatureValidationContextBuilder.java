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
import java.util.HashMap;
import java.util.Map;

import javax.xml.transform.TransformerException;

import oasis.names.tc.dss._1_0.core.schema.SignatureObject;

import jakarta.xml.bind.JAXBException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;

import de.bund.bsi.tr_esor.checktool.Toolbox;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;
import de.bund.bsi.tr_esor.checktool.xml.XaipSerializer;
import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.DataObjectType;


/**
 * Builder for detached signature validation context.
 *
 * @author PRE
 */
public class DetachedSignatureValidationContextBuilder
{

  private XaipSerializer xaipSerializer;

  private String profileName = "";

  private boolean restrictedValidation;

  /**
   * @param serializer xaip serializer which is required by builder
   * @return this (fluid api)
   */
  public DetachedSignatureValidationContextBuilder withXaipSerializer(XaipSerializer serializer)
  {
    this.xaipSerializer = serializer;
    return this;
  }

  /**
   * @param profileName configuration profile to be used
   * @return this (fluid api)
   */
  public DetachedSignatureValidationContextBuilder withProfileName(String profileName)
  {
    this.profileName = profileName;
    return this;
  }

  /**
   * Set to <code>true</code> if some validations cannot be done in given context
   *
   * @return this (fluid api)
   */
  public DetachedSignatureValidationContextBuilder withRestrictedValidation(boolean value)
  {
    this.restrictedValidation = value;
    return this;
  }

  /**
   * Creates an instance of detached signature validation context.
   */
  public DetachedSignatureValidationContext create(CredentialType cred) throws IOException
  {
    Map<Reference, byte[]> protectedDataById = new HashMap<>();
    Map<Reference, String> extensionByRef = new HashMap<>();
    Reference ref = new Reference(cred.getCredentialID());

    prepareReferenceSignatureValue(ref, cred);
    for ( Object covered : cred.getRelatedObjects() )
    {
      try
      {
        Reference refToProtectedElem = ref.newChild(Toolbox.getId(covered));
        protectedDataById.put(refToProtectedElem, xaipSerializer.serializeForSignatureVerification(covered));
        if (covered instanceof DataObjectType)
        {
          extensionByRef.put(refToProtectedElem, Toolbox.getPreferredExtension((DataObjectType)covered));
        }
      }
      catch (CanonicalizationException | InvalidCanonicalizerException | JAXBException e)
      {
        throw new IOException(e);
      }
    }

    return new DetachedSignatureValidationContext(ref, cred.getSignatureObject(), protectedDataById,
                                                  profileName).withPreferredExtensions(extensionByRef)
                                                              .withSerializer(xaipSerializer)
                                                              .withRestrictedValidation(restrictedValidation);
  }

  @SuppressWarnings("PMD.ConfusingTernary")
  private void prepareReferenceSignatureValue(Reference ref, CredentialType cred)
  {
    var sig = cred.getSignatureObject();
    if (sig == null)
    {
      var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory(profileName));
      var binaryData = lXaipReader.readBinaryData(cred, cred.getCredentialID());
      ref.setSignatureValue(binaryData);
      return;
    }

    if (sig.getTimestamp() != null)
    {
      ref.setSignatureValue(sig.getTimestamp().getRFC3161TimeStampToken());
    }
    else if (sig.getBase64Signature() != null)
    {
      ref.setSignatureValue(sig.getBase64Signature().getValue());
    }
    else
    {
      // expecting ds:Signature to be present
      ref.setSignatureValue(serializeXmlSignature(ref.toString(), sig));
    }
  }

  private byte[] serializeXmlSignature(String credentialId, SignatureObject sig)
  {
    try
    {
      return xaipSerializer.serializeXmlSignatureFromCredential(credentialId, sig);
    }
    catch (TransformerException | CanonicalizationException | InvalidCanonicalizerException | JAXBException
      | IOException e)
    {
      throw new IllegalStateException("cannot serialized parsed object", e);
    }
  }
}
