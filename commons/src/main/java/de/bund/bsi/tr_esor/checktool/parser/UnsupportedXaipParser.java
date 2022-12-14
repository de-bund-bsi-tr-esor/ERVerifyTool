package de.bund.bsi.tr_esor.checktool.parser;

import java.io.IOException;

import de.bund.bsi.tr_esor.checktool.data.UnsupportedData;


/** Matches Tags for ESOR 1.1 and ESOR 1.2 XAIP */
public class UnsupportedXaipParser extends RegexBasedParser
{

  /** create a parser that checks for unsupported XAIPs */
  public UnsupportedXaipParser()
  {
    super(regexForMainTag("XAIP", "http://(www.)?bsi.bund.de/tr-esor/xaip/1.[2|1]"));
  }

  @Override
  public Object parse() throws IOException
  {
    return new UnsupportedData("A XAIP that does not conform to the XAIP version supported by this tool was found.");
  }
}
