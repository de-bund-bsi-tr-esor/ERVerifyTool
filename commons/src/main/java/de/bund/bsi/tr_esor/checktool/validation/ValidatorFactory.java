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
package de.bund.bsi.tr_esor.checktool.validation;

import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import oasis.names.tc.dss._1_0.core.schema.SignatureObject;

import org.bouncycastle.tsp.TimeStampToken;

import de.bund.bsi.tr_esor.checktool._1.ConfigurableObjectType;
import de.bund.bsi.tr_esor.checktool._1.ParameterType;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.conf.ValidatorRepository;
import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampChain;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampSequence;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.data.InlineSignedData;
import de.bund.bsi.tr_esor.checktool.hash.HashCreator;
import de.bund.bsi.tr_esor.checktool.hash.LocalHashCreator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.AlgorithmUsageValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.ArchiveTimeStampChainValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.ArchiveTimeStampSequenceValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.ArchiveTimeStampValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.DummyTimeStampValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.ECardTimeStampValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.EvidenceRecordValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.NoVerificationValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsAlgorithmUsageValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsArchiveTimeStampChainValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsArchiveTimeStampSequenceValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsArchiveTimeStampValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsDummyTimeStampValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsEvidenceRecordValidator;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSChainReport;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSSequenceReport;
import de.bund.bsi.tr_esor.checktool.validation.report.AlgorithmValidityReport;
import de.bund.bsi.tr_esor.checktool.validation.report.ArchiveTimeStampReport;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.SignatureReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.validation.signatures.DetachedSignatureValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.signatures.ECardDetachedSignatureValidator;
import de.bund.bsi.tr_esor.checktool.validation.signatures.ECardInlineSignatureValidator;
import de.bund.bsi.tr_esor.checktool.validation.signatures.InlineSignatureValidationContext;


/**
 * Provides validator classes according to current configuration.
 *
 * @author TT
 */
public final class ValidatorFactory
{

    private static final ValidatorRepository BUILT_IN = new ValidatorRepository();

    private static final ValidatorFactory INSTANCE = new ValidatorFactory();

    static
    {
        BUILT_IN.addGeneral(AlgorithmUsageValidator::new, AlgorithmUsage.class, ValidationContext.class, AlgorithmValidityReport.class);
        BUILT_IN.addGeneral(EvidenceRecordValidator::new, EvidenceRecord.class, ErValidationContext.class, EvidenceRecordReport.class);
        BUILT_IN.addGeneral(ArchiveTimeStampSequenceValidator::new,
            ArchiveTimeStampSequence.class,
            ErValidationContext.class,
            ATSSequenceReport.class);
        BUILT_IN.addGeneral(ArchiveTimeStampChainValidator::new,
            ArchiveTimeStampChain.class,
            ErValidationContext.class,
            ATSChainReport.class);
        BUILT_IN.addGeneral(ArchiveTimeStampValidator::new,
            ArchiveTimeStamp.class,
            ErValidationContext.class,
            ArchiveTimeStampReport.class);
        BUILT_IN.addGeneral(DummyTimeStampValidator::new, TimeStampToken.class, ValidationContext.class, TimeStampReport.class);
        // check for alternatives to ECard
        BUILT_IN.addGeneral(ECardInlineSignatureValidator::new,
            InlineSignedData.class,
            InlineSignatureValidationContext.class,
            SignatureReportPart.class);
        BUILT_IN.addGeneral(ECardDetachedSignatureValidator::new,
            SignatureObject.class,
            DetachedSignatureValidationContext.class,
            SignatureReportPart.class);
        BUILT_IN.addGeneral(NoVerificationValidator::new, Object.class, NoVerificationContext.class, ReportPart.class);

        /* The RFC4998 profile contains the default validators, so no others are configured here */
        BUILT_IN.addProfile(ProfileNames.RFC4998);

        /* The TR-ESOR profile requires an online check for timestamps to be done. */
        BUILT_IN.addProfile(ProfileNames.TR_ESOR);
        BUILT_IN.addToProfile(ECardTimeStampValidator::new,
            TimeStampToken.class,
            ValidationContext.class,
            TimeStampReport.class,
            ProfileNames.TR_ESOR);

        BUILT_IN.addToProfile(BasisErsAlgorithmUsageValidator::new,
            AlgorithmUsage.class,
            ValidationContext.class,
            AlgorithmValidityReport.class,
            ProfileNames.BASIS_ERS);
        BUILT_IN.addToProfile(BasisErsArchiveTimeStampValidator::new,
            ArchiveTimeStamp.class,
            ErValidationContext.class,
            ArchiveTimeStampReport.class,
            ProfileNames.BASIS_ERS);
        BUILT_IN.addToProfile(BasisErsArchiveTimeStampSequenceValidator::new,
            ArchiveTimeStampSequence.class,
            ErValidationContext.class,
            ATSSequenceReport.class,
            ProfileNames.BASIS_ERS);
        BUILT_IN.addToProfile(BasisErsArchiveTimeStampChainValidator::new,
            ArchiveTimeStampChain.class,
            ErValidationContext.class,
            ATSChainReport.class,
            ProfileNames.BASIS_ERS);
        BUILT_IN.addToProfile(BasisErsEvidenceRecordValidator::new,
            EvidenceRecord.class,
            ErValidationContext.class,
            EvidenceRecordReport.class,
            ProfileNames.BASIS_ERS);
        BUILT_IN.addToProfile(BasisErsDummyTimeStampValidator::new,
            TimeStampToken.class,
            ValidationContext.class,
            TimeStampReport.class,
            ProfileNames.BASIS_ERS);
    }

    private ValidatorFactory()
    {
        // nobody else
    }

    /**
     * Singleton getter.
     */
    public static ValidatorFactory getInstance()
    {
        return INSTANCE;
    }

    /**
     * Returns a validator to check an object of given type and returning the required report type. If a validator is configured, it must be
     * returned. Otherwise, a default instance will be returned. The eventually chosen validator may support more general parameter classes
     * but the caller gets what he or she asked for.
     *
     * @param targetClass
     * @param reportClass
     * @param context
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    public <T, C extends ValidationContext, R extends ReportPart> Validator<T, C, R> getValidator(Class<T> targetClass,
        Class<R> reportClass, C context)
    {

        var profileName = context.getProfileName();
        var sup = Optional.ofNullable(Configurator.getInstance().getValidators())
            .map(r -> r.get(targetClass, context.getClass(), reportClass, profileName))
            .orElse(BUILT_IN.get(targetClass, context.getClass(), reportClass, profileName));
        var result = (Validator<T, C, R>)Optional.ofNullable(sup)
            .map(Supplier::get)
            .orElseThrow(() -> new NoValidatorException(targetClass.getName(), context, reportClass.getName()));
        result.setContext(context);
        return result;
    }

    /**
     * Returns the configured instance of {@link HashCreator}.
     *
     * @throws ReflectiveOperationException
     */
    public HashCreator getHashCreator() throws ReflectiveOperationException
    {
        var config = Configurator.getInstance();
        var cnf = config.getHashCreator();
        if (cnf == null)
        {
            return new LocalHashCreator();
        }
        return (HashCreator)createInstance(cnf, Class.forName(cnf.getClassName()));
    }

    /**
     * Returns <code>true</code> if a built-in or configured profile with given name is supported.
     *
     * @param profileName
     */
    public boolean isProfileSupported(String profileName)
    {
        return BUILT_IN.containsProfile(profileName) || Configurator.getInstance().isProfileSupported(profileName);
    }

    private static <T> T createInstance(ConfigurableObjectType cnf, Class<T> clazz) throws ReflectiveOperationException
    {
        var params = cnf.getParameter().stream().collect(Collectors.toMap(ParameterType::getName, ParameterType::getValue));
        try
        {
            return clazz.getConstructor(Map.class).newInstance(params);
        }
        catch (NoSuchMethodException e)
        {
            if (!params.isEmpty())
            {
                throw e;
            }
            return clazz.getDeclaredConstructor().newInstance();
        }
    }
}
