/*-
 * Copyright (c) 2017
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
package de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.bund.bsi.ecard.api._1.ECard;
import de.bund.bsi.ecard.api._1.ECard_Service;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.TestECardTimeStampValidator;


/**
 * Offline checks for BasisErsECardTimeStampValidator.
 */
public class TestBasisErsECardTimeStampValidator extends TestECardTimeStampValidator
{

  @Override
  protected BasisErsECardTimeStampValidator sut(String url)
  {
    var profile = Configurator.getInstance().getProfile(Configurator.getInstance().getDefaultProfileName());
    profile.setValidationService(url);
    return new BasisErsECardTimeStampValidator();
  }

  @Override
  protected BasisErsECardTimeStampValidator sut(ECard ecard)
  {
    ECard_Service eCardWebservice = when(mock(ECard_Service.class).getECard()).thenReturn(ecard).getMock();
    return new BasisErsECardTimeStampValidator(eCardWebservice);
  }

}
