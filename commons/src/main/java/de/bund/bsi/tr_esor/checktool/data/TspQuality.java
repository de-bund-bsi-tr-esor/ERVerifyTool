package de.bund.bsi.tr_esor.checktool.data;

import java.util.Arrays;
import java.util.stream.Collectors;

import org.etsi.uri._19102.v1_2.SignatureQualityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 * Enum for timestamp qualities. This enum will currently handle the URIs that end in the given statements.
 * Such URIs might be found inside a SignatureQualityType as defined for the ETSI SignatureValidationReport.
 */
@SuppressWarnings({"PMD.FieldNamingConventions", "java:S115"})
public enum TspQuality
{

  /**
   * Qualified results
   */
  // Generic result for qualified timestaps. Generally, QTST_EUMS_TL is expected instead of this in new
  // versions.
  QTST("QTST", true),

  // qualified European timestamp (EUMS-TL).
  QTST_EUMS_TL("QTST_EUMS_TL", true),

  // qualified electronic timestamp according to German signature law (created before 30.06.2016)
  QTST_SIGG_EUMS_TL("QTST_SIGG_EUMS_TL", true),

  /**
   * Non-qualified, but comprehensively checked results
   */
  // Generic result for timestamps from non-qualified sources, new versions use more specific cases below.
  TSA("TSA", false),

  // non-qualified electronic timestamp of a qVDA for augmentation of QES (EUMS-TL).
  TSA_TSS_QC_EUMS_TL("TSA_TSS_QC_EUMS_TL", false),

  // non-qualified electronic timestamp of a VDA for augmentation of QES (EUMS-TL).
  TSA_TSS_AdES_QC_AND_QES_EUMS_TL("TSA_TSS_AdES_QC_AND_QES_EUMS_TL", false),

  // non-qualified electronic timestamp (EUMS-TL).
  TSA_EUMS_TL("TSA_EUMS_TL", false),

  // non-qualified electronic timestamp (Governikus-TL).
  TSA_GOV_TL("TSA_GOV_TL", false),

  // non-qualified electronic timestamp of a qVDA for augmentation of QES (Governikus-TL).
  TSA_TSS_QC_GOV_TL("TSA_TSS_QC_GOV_TL", false),

  // non-qualified electronic timestamp of a VDA for augmentation of QES (Governikus-TL).
  TSA_TSS_AdES_QC_AND_QES_GOV_TL("TSA_TSS_AdES_QC_AND_QES_GOV_TL", false),

  // non-qualified electronic timestamp (Custom TL).
  TSA_CUSTOM_TL("TSA_CUSTOM_TL", false),

  // non-qualified electronic timestamp of a qVDA for augmentation of QES (Custom-TL).
  TSA_TSS_QC_CUSTOM_TL("TSA_TSS_QC_CUSTOM_TL", false),

  // non-qualified electronic timestamp of a VDA for augmentation of QES (Custom-TL).
  TSA_TSS_AdES_QC_AND_QES_CUSTOM_TL("TSA_TSS_AdES_QC_AND_QES_CUSTOM_TL", false),

  /**
   * timestamps that could not be comprehensively validated
   */
  // Digital time stamp token. NO quality could be determined. Expected for development timestamps.
  DTST("DTST", false),

  // requirements for non-qualified electronic timestamp (EUMS-TL) not fulfilled.
  NO_TSA_EUMS_TL("NO_TSA_EUMS_TL", false),

  // no non-qualified electronic timestamp of a qVDA for augmentation of QES (EUMS-TL).
  NO_TSA_TSS_QC_EUMS_TL("TSA_TSS_QC_EUMS_TL", false),

  // no non-qualified electronic timestamp of a VDA for augmentation of QES (EUMS-TL)
  NO_TSA_TSS_AdES_QC_AND_QES_EUMS_TL("NO_TSA_TSS_AdES_QC_AND_QES_EUMS_TL", false),

  // requirements for qualified European timestamp (EUMS-TL) not fulfilled.
  NO_QTST_EUMS_TL("NO_QTST_EUMS_TL", false),

  // no qualified electronic timestamp according to German signature law (created before 30.06.2016)
  NO_QTST_SIGG_EUMS_TL("NO_QTST_SIGG_EUMS_TL", false);

  private static final Logger LOG = LoggerFactory.getLogger(TspQuality.class);

  private final String quality;

  private final boolean isQualified;

  private String uri;

  TspQuality(String quality, boolean isQualified)
  {
    this.quality = quality;
    this.isQualified = isQualified;
  }

  private void setUri(String uri)
  {
    this.uri = uri;
  }

  /**
   * creates enum value from {@link SignatureQualityType} nested URI value
   */
  public static TspQuality from(String uri)
  {
    var split = uri.split("/");
    var quality = split[split.length - 1];
    var results = Arrays.stream(values()).filter(e -> e.quality.equals(quality)).collect(Collectors.toList());
    if (results.isEmpty())
    {
      throw new IllegalArgumentException("Cannot determine timestamp quality from URI " + uri);
    }
    if (results.size() > 1)
    {
      throw new IllegalArgumentException("Timestamp quality determined from URI " + uri
                                         + " is ambiguous. Following qualities match the uri: " + results);
    }
    var tspQuality = results.get(0);
    tspQuality.setUri(uri);
    return tspQuality;
  }

  /** get the URI as provided in the SignatureQuality element */
  public String uri()
  {
    return uri;
  }

  /**
   * Qualification status derived from the result. Will be true only for comprehensively checked timestamps
   * from qualified providers according to the official trusted lists
   */
  public boolean isQualified()
  {
    return isQualified;
  }

  @Override
  public String toString()
  {
    return uri();
  }
}
