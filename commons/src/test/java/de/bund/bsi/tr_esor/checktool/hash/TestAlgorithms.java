package de.bund.bsi.tr_esor.checktool.hash;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;


/**
 * Test class for the algorithm utility class
 */
@SuppressWarnings({"PMD.CommentRequired", "checkstyle:JavadocMethod"})
public class TestAlgorithms
{

  @Test
  public void mapsAlgorithmIdentifierToOid() throws NoSuchAlgorithmException
  {
    var oid = Algorithms.toOid("http://www.w3.org/2001/04/xmlenc#sha256");
    assertThat(oid, is("2.16.840.1.101.3.4.2.1"));

    oid = Algorithms.toOid("http://www.w3.org/2000/09/xmldsig#sha1");
    assertThat(oid, is("1.3.14.3.2.26"));

    oid = Algorithms.toOid("http://www.w3.org/2001/04/xmldsig-more#sha224");
    assertThat(oid, is("2.16.840.1.101.3.4.2.4"));

    oid = Algorithms.toOid("http://www.w3.org/2001/04/xmldsig-more#sha384");
    assertThat(oid, is("2.16.840.1.101.3.4.2.2"));

    oid = Algorithms.toOid("http://www.w3.org/2001/04/xmlenc#sha512");
    assertThat(oid, is("2.16.840.1.101.3.4.2.3"));
  }

  @Test
  public void throwsOnUnknownAlgorithmIdentifier()
  {
    var actual = assertThrows(NoSuchAlgorithmException.class, () -> Algorithms.toOid("tolle id"));
    assertThat(actual.getMessage(), containsString("tolle id"));
  }

  @Test
  public void throwsOnNull()
  {
    assertThrows(NoSuchAlgorithmException.class, () -> Algorithms.toOid(null));
  }
}
