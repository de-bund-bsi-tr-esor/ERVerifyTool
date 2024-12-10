package de.bund.bsi.tr_esor.checktool;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.data.XaipAndSerializer;
import de.bund.bsi.tr_esor.checktool.out.OutputFolder;
import de.bund.bsi.tr_esor.checktool.out.XaipObjectWriter;
import de.bund.bsi.tr_esor.checktool.validation.signatures.DetachedSignatureValidationContextBuilder;
import de.bund.bsi.tr_esor.checktool.xml.ComprehensiveXaipSerializer;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.xaip.PackageHeaderType;
import de.bund.bsi.tr_esor.xaip.XAIPType;

import jakarta.xml.bind.JAXBException;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Extracts data from xaips and writes them as files to specified output folder. Writes verification reports to outputfolder.
 */
public class DumpHandler
{

    private static final Logger LOG = LoggerFactory.getLogger(DumpHandler.class);


    private final OutputFolder outputFolder;

    /**
     * Constructor
     */
    public DumpHandler(OutputFolder outputFolder)
    {
        this.outputFolder = outputFolder;
    }

    /**
     * Extracts data from XAIP and writes them to the output folder.
     */
    public void dumpXaip(XAIPType xaip, ComprehensiveXaipSerializer serializer, LXaipReader lXaipReader, String profile) throws IOException
    {
        var xas = new XaipAndSerializer(xaip, serializer);
        var aoid = Optional.ofNullable(xas.getXaip()).map(XAIPType::getPackageHeader).map(PackageHeaderType::getAOID).orElse("no_aoid");
        outputFolder.createAoidFolder(aoid);
        dumpDataSection(xas, outputFolder);
        dumpSignature(xas, outputFolder, lXaipReader, profile);
    }

    @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
    private void dumpDataSection(XaipAndSerializer xas, OutputFolder outFolder)
    {
        var dataSection = xas.getXaip().getDataObjectsSection();
        if (dataSection == null)
        {
            LOG.info("no data section");
            return;
        }
        var xaipObjectWriter = new XaipObjectWriter().withOutputFolder(outFolder).withXaipSerializer(xas.getSerializer());
        for (var data : dataSection.getDataObject())
        {
            xaipObjectWriter.write(data);
        }
    }

    @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
    private void dumpSignature(XaipAndSerializer xas, OutputFolder outFolder, LXaipReader lXaipReader, String profileName)
        throws IOException
    {
        var credentialSection = xas.getXaip().getCredentialsSection();
        if (credentialSection == null)
        {
            LOG.info("no credential section");
            return;
        }
        var xaipObjectWriter = new XaipObjectWriter().withOutputFolder(outFolder).withXaipSerializer(xas.getSerializer());
        for (var cred : credentialSection.getCredential())
        {
            var sigObj = cred.getSignatureObject();
            if (sigObj != null && isSupportedSignatureObject(sigObj))
            {
                var ctx = new DetachedSignatureValidationContextBuilder().withXaipSerializer(xas.getSerializer()).create(cred);
                xaipObjectWriter.write(ctx);
            }
            else if (cred.getOther() != null)
            {
                if (lXaipReader.isValidLXaipElement(cred, cred.getCredentialID()))
                {
                    var ctx = new DetachedSignatureValidationContextBuilder().withXaipSerializer(xas.getSerializer())
                        .withProfileName(profileName)
                        .create(cred);
                    xaipObjectWriter.write(ctx);
                }
                else
                {
                    LOG.warn(
                        "Credential {} is not a supported signature object. For Credentials containing xaip:other, only LXAIP data references are supported.",
                        cred.getCredentialID());
                }

            }
            else
            {
                LOG.warn(
                    "Credential {} is not a supported signature object. Supported are: http://www.w3.org/2000/09/xmldsig#Signature, dss:Timestamp and dss:Base64Signature",
                    cred.getCredentialID());
            }
        }
    }

    /**
     * Writes the VerificationReport to the output folder.
     */
    public void dumpReport(VerificationReportType report) throws IOException, JAXBException
    {
        var destFolder = outputFolder.getAoidFolder() == null ? outputFolder.noAoidDestinationFolder() : outputFolder.getAoidFolder();
        try (OutputStream outs = new FileOutputStream(Paths.get(destFolder.toString(), "report.xml").toAbsolutePath().toString()))
        {
            XmlHelper.serialize(report, outs);
        }
    }

    private boolean isSupportedSignatureObject(SignatureObject sigObj)
    {
        return sigObj.getBase64Signature() != null || sigObj.getSignature() != null || sigObj.getTimestamp() != null;
    }
}
