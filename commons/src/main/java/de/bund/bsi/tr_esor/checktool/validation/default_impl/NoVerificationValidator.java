package de.bund.bsi.tr_esor.checktool.validation.default_impl;

import de.bund.bsi.tr_esor.checktool.validation.NoVerificationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.xml.LXaipDigestMismatchException;


/**
 * Dummy validator that transfers the reason given for verification being impossible in the context into an appropriate report part.
 *
 * @author ETR
 */
public class NoVerificationValidator extends BaseValidator<Object, NoVerificationContext, ReportPart>
{

    @Override
    protected Class<NoVerificationContext> getRequiredContextClass()
    {
        return NoVerificationContext.class;
    }

    @Override
    protected ReportPart validateInternal(Reference ref, Object toCheck)
    {
        if (ctx.getException() instanceof LXaipDigestMismatchException)
        {
            return ReportPart.forLXaipDigestMismatch(ref, ctx.getException());
        }
        return ReportPart.forNoVerification(ref, ctx.getReason());
    }
}
