package de.bund.bsi.tr_esor.checktool.hash;

import java.security.NoSuchAlgorithmException;
import java.util.Map;


/**
 * Required and optional algorithms of xml dsig standard https://www.w3.org/TR/xmldsig-core1/#sec-AlgID
 *
 * @author SMU
 */
public final class Algorithms
{

  private static final Map<String, String> ALGORITHM_MAP = Map.of("http://www.w3.org/2000/09/xmldsig#sha1",
                                                                  "1.3.14.3.2.26",
                                                                  "http://www.w3.org/2001/04/xmldsig-more#sha224",
                                                                  "2.16.840.1.101.3.4.2.4",
                                                                  "http://www.w3.org/2001/04/xmlenc#sha256",
                                                                  "2.16.840.1.101.3.4.2.1",
                                                                  "http://www.w3.org/2001/04/xmldsig-more#sha384",
                                                                  "2.16.840.1.101.3.4.2.2",
                                                                  "http://www.w3.org/2001/04/xmlenc#sha512",
                                                                  "2.16.840.1.101.3.4.2.3");

  /**
   * Returns oid for xml dsig standard identifier
   */
  public static String toOid(String algorithmIdentifier) throws NoSuchAlgorithmException
  {
    if (algorithmIdentifier == null || !ALGORITHM_MAP.containsKey(algorithmIdentifier))
    {
      throw new NoSuchAlgorithmException("Unknown digest algorithm: " + algorithmIdentifier);
    }
    return ALGORITHM_MAP.get(algorithmIdentifier);
  }
}
