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
package de.bund.bsi.tr_esor.checktool.conf;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;


/**
 * Selects Validators respective to its target class according to the best matching class (as a Java VM
 * selects an overwritten method).
 *
 * @author HMA, TT
 */
public class ValidatorRepository
{

  private static class ProfileRepo
  {

    private static class ValidatorSource
    {

      Supplier<Object> supplier;

      Class<?> contextClass;

      Class<?> reportClass;

      ValidatorSource(Supplier<Object> supplier, Class<?> contextClass, Class<?> reportClass)
      {
        this.supplier = supplier;
        this.contextClass = contextClass;
        this.reportClass = reportClass;
      }
    }

    private final Map<Class<?>, ValidatorSource> byTarget = new HashMap<>();

    ProfileRepo()
    {
      // just for visibility
    }

    @SuppressWarnings("rawtypes") // ValidationContext
    Supplier<Object> get(Class<?> target,
                         Class<? extends ValidationContext> contextClass,
                         Class<? extends ReportPart> reportClass)
    {
      return byTarget.entrySet()
                     .stream()
                     .filter(e -> e.getKey().isAssignableFrom(target))
                     .filter(e -> e.getValue().contextClass.isAssignableFrom(contextClass))
                     .filter(e -> reportClass.isAssignableFrom(e.getValue().reportClass))
                     .sorted((a, b) -> countInheritanceSteps(b.getKey(), target)
                                       - countInheritanceSteps(a.getKey(), target))
                     .map(e -> e.getValue().supplier)
                     .findFirst()
                     .orElse(null);
    }

    void add(Supplier<Object> supplier, Class<?> target, Class<?> contextClass, Class<?> reportClass)
    {
      byTarget.put(target, new ValidatorSource(supplier, contextClass, reportClass));
    }

    private int countInheritanceSteps(Class<?> a, Class<?> b)
    {
      int result = 0;
      Class<?> intermed = a;
      while (intermed != null && intermed.isAssignableFrom(b))
      {
        result++;
        intermed = intermed.getSuperclass();
      }
      return result - 1;
    }
  }

  private final ProfileRepo general = new ProfileRepo();

  private final Map<String, ProfileRepo> byProfile = new HashMap<>();

  /**
   * Returns the object specified by target class and profile. If the profile does not contain any such value,
   * chooses it from general set.
   *
   * @param target
   * @param profileName
   */
  public Supplier<Object> get(Class<?> target,
                              // Java cannot handle ? extends ValidationContext<?> properly.
                              @SuppressWarnings("rawtypes") Class<? extends ValidationContext> contextClass,
                              Class<? extends ReportPart> reportClass,
                              String profileName)
  {
    return Optional.ofNullable(byProfile.get(profileName))
                   .map(m -> m.get(target, contextClass, reportClass))
                   .orElse(general.get(target, contextClass, reportClass));
  }

  /**
   * Adds a value suitable for all supported profiles.
   *
   * @param supplier
   * @param target
   * @param contextClass
   * @param reportClass
   */
  public void addGeneral(Supplier<Object> supplier,
                         Class<?> target,
                         @SuppressWarnings("rawtypes") Class<? extends ValidationContext> contextClass,
                         Class<? extends ReportPart> reportClass)
  {
    general.add(supplier, target, contextClass, reportClass);
  }

  /**
   * Adds a profile name.
   *
   * @param profile
   */
  public void addProfile(String profile)
  {
    if (!containsProfile(profile))
    {
      byProfile.put(profile, new ProfileRepo());
    }
  }

  /**
   * Adds a value for a special profile.
   *
   * @param supplier
   * @param target
   * @param contextClass
   * @param reportClass
   * @param profile
   */
  public void addToProfile(Supplier<Object> supplier,
                           Class<?> target,
                           @SuppressWarnings("rawtypes") Class<? extends ValidationContext> contextClass,
                           Class<? extends ReportPart> reportClass,
                           String profile)
  {
    if (profile == null)
    {
      general.add(supplier, target, contextClass, reportClass);
    }
    else
    {
      addProfile(profile);
      byProfile.get(profile).add(supplier, target, contextClass, reportClass);
    }
  }

  /**
   * Returns <code>true</code> if specified profile is supported.
   *
   * @param profile
   */
  public boolean containsProfile(String profile)
  {
    return byProfile.containsKey(profile);
  }


}
