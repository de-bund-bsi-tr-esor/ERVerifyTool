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
package de.bund.bsi.tr_esor.checktool.json;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.Map;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.junit.Before;
import org.junit.Test;


/**
 * Tests native Java JSON serialization.
 *
 * @author BVO
 */
public class TestNativeJsonParsing
{


  private ScriptEngine engine;

  /**
   * Initializes the Nashorn ScriptEngine.
   */
  @Before
  public void initEngine()
  {
    ScriptEngineManager sem = new ScriptEngineManager();
    this.engine = sem.getEngineByName("javascript");
  }

  /**
   * Asserts that native JSON parsing is possible.
   *
   * @throws IOException
   * @throws ScriptException
   */
  @Test
  public void parseJson() throws IOException, ScriptException
  {
    String json = "{\"person\": {\"erster\": {\"name\":\"herbert\"} }}";
    String script = "Java.asJSONCompatible(" + json + ")";
    Object result = this.engine.eval(script);
    @SuppressWarnings("unchecked")
    String name = ((Map<String, Map<String, Map<String, String>>>)result).get("person")
                                                                         .get("erster")
                                                                         .get("name");
    assertThat("Parsed Name", name, is("herbert"));
  }
}
