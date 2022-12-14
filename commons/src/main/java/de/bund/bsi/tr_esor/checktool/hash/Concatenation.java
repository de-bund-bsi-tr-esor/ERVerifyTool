package de.bund.bsi.tr_esor.checktool.hash;

/**
 * Concatenation operations on hashes
 */
public class Concatenation
{

  /**
   * Concats two byte arrays
   */
  public static byte[] concat(byte[] b1, byte[] b2)
  {
    var result = new byte[b1.length + b2.length];
    System.arraycopy(b1, 0, result, 0, b1.length);
    System.arraycopy(b2, 0, result, b1.length, b2.length);
    return result;
  }

}
