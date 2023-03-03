package de.bund.bsi.tr_esor.checktool.xml;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import jakarta.xml.bind.JAXBElement;

import org.etsi.uri._02918.v1_2.DataObjectReferenceType;
import org.w3._2000._09.xmldsig_.DigestMethodType;

import de.bund.bsi.tr_esor.checktool.hash.Algorithms;
import de.bund.bsi.tr_esor.checktool.hash.LocalHashCreator;
import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.DataObjectType;
import de.bund.bsi.tr_esor.xaip.MetaDataObjectType;


/**
 * Handles LXAIP data objects
 *
 * @author SMU, FAS
 */
public class LXaipReader
{

  private final Path lxaipDataDirectory;

  /**
   *
   */
  public LXaipReader(Path lxaipDataDirectory)
  {
    this.lxaipDataDirectory = lxaipDataDirectory;
  }

  /**
   *
   */
  public static boolean isValidLXaipElement(Object data, String id)
  {
    return isLXaip(data) && isValidOrThrow(dataObjectReferenceFrom(data), id);
  }

  /**
   *
   */
  public byte[] readBinaryData(Object data, String id)
  {
    var dataObjectReference = dataObjectReferenceFrom(data);
    var path = resolvePath(dataObjectReference.getURI(), id);

    try (InputStream fi = new FileInputStream(path.toFile()); InputStream ins = new BufferedInputStream(fi))
    {
      var binaryData = ins.readAllBytes();
      var digestCorrect = isDigestCorrect(binaryData,
                                          dataObjectReference.getDigestMethod(),
                                          dataObjectReference.getDigestValue());
      if (!digestCorrect)
      {
        throw new LXaipDigestMismatchException(String.format("The calculated digest value of the LXAIP data object (id: %s) does not match the embedded digest",
                                                             id),
                                               id);
      }

      return binaryData;
    }
    catch (IOException e)
    {
      throw new LXaipUnprocessableException(String.format("Cannot read LXAIP's data object (id: %s) from file %s. Adjust lxaipDataDirectory configuration and/or the LXAIP uri accordingly",
                                                          id,
                                                          path.toAbsolutePath()),
                                            id, e);
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new LXaipUnprocessableException(String.format("The LXAIP digest method of the data object reference (id: %s) is unknown",
                                                          id),
                                            id, e);
    }
  }

  private Path resolvePath(String uri, String dataObjectId)
  {
    var path = lxaipDataDirectory.resolve(uri);
    ensureNoDirectoryTraversal(lxaipDataDirectory, path, dataObjectId);
    return path;
  }

  private static void ensureNoDirectoryTraversal(Path directory, Path fileWithin, String dataObjectId)
  {
    try
    {
      if (!fileWithin.toFile().getCanonicalPath().startsWith(directory.toFile().getCanonicalPath()))
      {
        throw new LXaipUnprocessableException(String.format("LXAIP data object (id: %s) reference uri is not allowed. Avoid using '..'. Not allowed was: %s",
                                                            dataObjectId,
                                                            fileWithin),
                                              dataObjectId);
      }
    }
    catch (IOException e)
    {
      throw new LXaipUnprocessableException(String.format("LXAIP data object (id: %s) reference uri cannot be resolved. (%s)",
                                                          dataObjectId,
                                                          fileWithin),
                                            dataObjectId, e);
    }
  }

  private boolean isDigestCorrect(byte[] binaryData, DigestMethodType digestMethod, byte[] digestValue)
    throws NoSuchAlgorithmException
  {
    var digestAlgorithm = digestMethod.getAlgorithm();
    var hash = new LocalHashCreator().calculateHash(binaryData, Algorithms.toOid(digestAlgorithm));
    return Arrays.equals(hash, digestValue);
  }

  private static boolean isLXaip(Object data)
  {
    List<Object> xmlData = null;
    if (data instanceof DataObjectType)
    {
      var xml = ((DataObjectType)data).getXmlData();
      xmlData = xml == null ? null : xml.getAny();
    }
    if (data instanceof MetaDataObjectType)
    {
      var xml = ((MetaDataObjectType)data).getXmlMetaData();
      xmlData = xml == null ? null : xml.getAny();
    }
    if (data instanceof CredentialType)
    {
      var xml = ((CredentialType)data).getOther();
      xmlData = xml == null ? null : xml.getAny();
    }

    return xmlData != null && xmlData.size() == 1 && xmlData.get(0) != null
           && xmlData.get(0) instanceof JAXBElement && ((JAXBElement)xmlData.get(0)).getValue() != null
           && ((JAXBElement)xmlData.get(0)).getValue() instanceof DataObjectReferenceType;
  }

  private static DataObjectReferenceType dataObjectReferenceFrom(Object data)
  {
    if (data instanceof DataObjectType)
    {
      return (DataObjectReferenceType)((JAXBElement)((DataObjectType)data).getXmlData()
                                                                          .getAny()
                                                                          .get(0)).getValue();
    }
    if (data instanceof MetaDataObjectType)
    {
      return (DataObjectReferenceType)((JAXBElement)((MetaDataObjectType)data).getXmlMetaData()
                                                                              .getAny()
                                                                              .get(0)).getValue();
    }
    if (data instanceof CredentialType)
    {
      return (DataObjectReferenceType)((JAXBElement)((CredentialType)data).getOther()
                                                                          .getAny()
                                                                          .get(0)).getValue();
    }
    return null;
  }

  private static boolean isValidOrThrow(DataObjectReferenceType dataObjectReference, String dataObjectID)
  {
    var isValid = dataObjectReference.getDigestValue() != null
                  && dataObjectReference.getDigestMethod() != null
                  && dataObjectReference.getDigestMethod().getAlgorithm() != null;
    if (!isValid)
    {
      throw new LXaipUnprocessableException(String.format("Detected a LXAIP but its data object reference (id: %s) is incomplete",
                                                          dataObjectID),
                                            dataObjectID);
    }
    return true;
  }
}
