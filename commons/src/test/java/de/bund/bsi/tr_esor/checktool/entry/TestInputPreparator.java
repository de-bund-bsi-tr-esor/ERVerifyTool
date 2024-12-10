package de.bund.bsi.tr_esor.checktool.entry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.nio.file.Paths;

import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.validation.signatures.DetachedSignatureValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.signatures.InlineSignatureValidationContext;


public class TestInputPreparator
{

    @Test
    public void verifySignaturesWhenAttributeIsTrue() throws Exception
    {
        var params = prepareParams("/config.xml", "/xaip/xaip_cades-det-er-emb.xml", "Basis-ERS");

        var sut = new InputPreparator(params);

        var validations = sut.getValidations();
        assertThat(validations).filteredOn(InlineSignatureValidationContext.class::isInstance).isNotEmpty();
        assertThat(validations).filteredOn(DetachedSignatureValidationContext.class::isInstance).isNotEmpty();
    }

    @Test
    public void notVerifySignaturesWhenAttributeIsFalse() throws Exception
    {
        var params = prepareParams("/config.xml", "/xaip/xaip_cades-det-er-emb.xml", "verifySignaturesFalse");

        var sut = new InputPreparator(params);

        var validations = sut.getValidations();
        assertThat(validations).filteredOn(InlineSignatureValidationContext.class::isInstance).isEmpty();
        assertThat(validations).filteredOn(DetachedSignatureValidationContext.class::isInstance).isEmpty();
    }

    private ParameterFinder prepareParams(String pathToConfig, String pathToData, String profileName) throws Exception
    {
        var configurator = Configurator.getInstance();
        var configURL = InputPreparator.class.getResource(pathToConfig);
        assertNotNull(configURL);
        configurator.load(new FileInputStream(configURL.getFile()));
        var dataURL = InputPreparator.class.getResource(pathToData);
        assertNotNull(dataURL);
        var dataURI = Paths.get(dataURL.toURI());
        return new FileParameterFinder(dataURI, null, profileName);
    }

}
