package de.bund.bsi.tr_esor.checktool.validation.signatures;

import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBElement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 * Utility methods to handle responses provided by an eCard-Service.
 *
 * @author ETR
 */
public final class ECardResponseUtil
{

  private static final Logger LOG = LoggerFactory.getLogger(ECardResponseUtil.class);

  /**
   * Detects if the eCard result indicates that no signature has been found in the data by the eCard service.
   * Two cases of possible results are known for this case. In the first one, the major result OK is reported
   * but no report is generated. In the other case, a result major error is reported and the message is set to
   * "No Plugin Found". This indicates that a plugin-based signature-detection system has no plugin for the
   * given signature. In case other implementations of the eCard-interface produce different codes if no
   * signature could be found, they should be added herer.
   *
   * @param response Response from an eCard-Service
   * @return true to indicate that no signature was found.
   */
  static boolean isNoSignatureFound(ResponseBaseType response)
  {
    // In this case the result is OK, but no report was created as no signature was found
    if (ECardResultMajor.OK.equals(response.getResult().getResultMajor()))
    {
      JAXBElement<?> elem = (JAXBElement<?>)response.getOptionalOutputs().getAny().get(0);
      if (elem.getValue() instanceof VerificationReportType)
      {
        VerificationReportType vrt = (VerificationReportType)elem.getValue();
        return vrt.getIndividualReport().isEmpty();
      }
    }

    // These are two other known cases to report that no signature has been found.
    if (ECardResultMajor.ERROR.equals(response.getResult().getResultMajor()))
    {
      String resultMinor = response.getResult().getResultMinor();
      if (ECardResultMinor.SIGNATURE_FORMAT_NOT_SUPPORTED.equals(resultMinor))
      {
        return true;
      }

      InternationalStringType resultMessage = response.getResult().getResultMessage();
      if (resultMessage != null)
      {
        return ECardResultMessage.RESULTMESSAGE_NO_PLUGIN.equals(resultMessage.getValue());
      }
    }

    // Other cases indicate that data that could be validated was found
    return false;
  }

  /**
   * This function decides if an eCard result indicates that a valid report was produced or if a technical
   * error of the eCard service is indicated.
   *
   * @param response eCard response
   * @return true to indicate the validation was executed successfully (not indicating a valid signature)
   */
  @SuppressWarnings("PMD")
  static boolean isAcceptableECardResult(ResponseBaseType response)
  {
    if (ECardResultMajor.OK.equals(response.getResult().getResultMajor()))
    {
      return true;
    }

    String resultMajor = response.getResult().getResultMajor();

    // The set of possible result majors is limited and other Major results must not occur.
    if (!ECardResultMajor.WARNING.equals(resultMajor) && !ECardResultMajor.ERROR.equals(resultMajor))
    {
      LOG.error("Received unknown result major {} from eCard service.", resultMajor);
      return false;
    }

    String resultMinor = response.getResult().getResultMinor();

    if (resultMinor == null)
    {
      LOG.error("Received non-ok result major {} from eCard service, but no ResultMinor was received.",
                resultMajor);
      return false;
    }

    // A warning should always have a report attached.
    if (ECardResultMajor.WARNING.equals(resultMajor))
    {
      return true;
    }

    switch (resultMinor)
    {
      case ECardResultMinor.INTERNAL_ERROR:
      case ECardResultMinor.PARAMETER_ERROR:
      case ECardResultMinor.NO_PERMISSION:
      case ECardResultMinor.COMMUNICATION_ERROR:
      case ECardResultMinor.SIGNATURE_ALGORITHM_NOT_SUPPORTED:
      case ECardResultMinor.RESOLUTION_OF_OBJECT_REFERENCE_IMPOSSIBLE:
      case ECardResultMinor.TRANSFORMATION_ALGORITHM_NOT_SUPPORTED:
      case ECardResultMinor.HASH_ALGORITHM_NOT_SUPPORTED:
      case ECardResultMinor.UNKNOWN_VIEWER:
      case ECardResultMinor.CERTIFICATE_NOT_FOUND:
      case ECardResultMinor.SIGNATURE_FORMAT_NOT_SUPPORTED:
        return false;
      case ECardResultMinor.INVALID_SIGNATURE:
      case ECardResultMinor.CERTIFICATE_REVOKED:
      case ECardResultMinor.INVALID_CERTIFICATE_PATH:
      case ECardResultMinor.WRONG_MESSAGE_DIGEST:
      case ECardResultMinor.INVALID_SIGNATURE_FORMAT:
      case ECardResultMinor.HASH_ALGORITHM_NOT_SUITABLE:
      case ECardResultMinor.CERTIFICATE_CHAIN_INTERRUPTED:
      case ECardResultMinor.INVALID_CERTIFICATE_REFERENCE:
      case ECardResultMinor.CERTIFICATE_FORMAT_NOT_CORRECT:
      case ECardResultMinor.CERTIFICATE_PATH_NOT_VALIDATED:
      case ECardResultMinor.CERTIFICATE_STATUS_NOT_CHECKED:
      case ECardResultMinor.SIGNATURE_MANIFEST_NOT_CHECKED:
      case ECardResultMinor.SIGNATURE_MANIFEST_NOT_CORRECT:
      case ECardResultMinor.IMPROPER_REVOCATION_INFORMATION:
      case ECardResultMinor.SIGNATURE_ALGORITHM_NOT_SUITABLE:
      case ECardResultMinor.DETACHED_SIGNATURE_WITHOUT_E_CONTENT:
      case ECardResultMinor.SUITABILITY_OF_ALGORITHMS_NOT_CHECKED:
      case ECardResultMinor.REFERENCED_TIME_NOT_WITHIN_CERTIFICATE_VALIDITY_PERIOD:
        return true;
      default:
        LOG.error("Received unknown result minor {} from eCard service.", resultMinor);
        return false;
    }
  }
}
