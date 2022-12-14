package de.bund.bsi.tr_esor.checktool.conf;

import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Mode for sorting hash values after a rehash. This is needed as different TR implementations interpret the
 * evidence record standard in a different way. The verbatim interpretation of RFC4998 for ASN.1-based ERs is
 * used as a default here and proposes that hashes must not be sorted during a rehash.
 */
public enum HashSortingMode
{

  /**
   * hash according to RFC 4998 (section 5.2, point 4) without sorting the hashes.
   */
  UNSORTED,
  /**
   * sort the hashes binary ascending according to RFC 6283 (section 4.2.2, point 6).
   */
  SORTED,
  /**
   * allow both variants to pass
   */
  BOTH;

  private static final Logger LOG = LoggerFactory.getLogger(HashSortingMode.class);

  public static final HashSortingMode DEFAULT = UNSORTED;

  /**
   * Get appropriate mode for configuration string
   *
   * @param sortingMode string from configuration
   * @return value from this enum
   */
  public static HashSortingMode fromString(String sortingMode)
  {
    if (sortingMode == null)
    {
      return DEFAULT;
    }

    var configuredMode = sortingMode.toLowerCase(Locale.ROOT);
    switch (configuredMode)
    {
      case "unsorted":
        return HashSortingMode.UNSORTED;
      case "sorted":
        return HashSortingMode.SORTED;
      case "both":
        return HashSortingMode.BOTH;
      default:
        LOG.warn("Cannot understand mode {} for hash sorting. Valid values are unsorted, sorted and both. Using default hash mode \"unsorted\".",
                 sortingMode);
        return HashSortingMode.DEFAULT;
    }
  }
}
