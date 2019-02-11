Appendix: Internal data types
=============================

The ErVerifyTool provides default validators for the following types of objects
to validate:

* ``de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage``
* ``de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp``
* ``de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampChain``
* ``de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampSequence``
* ``de.bund.bsi.tr_esor.checktool.data.EvidenceRecord``
* ``org.bouncycastle.tsp.TimeStampToken``

See API documentation of the respective classes for further information.

This list may be extended in the following cases:

* A new parser is added which produces another type of object to validate.
* A new validator is added which encounters another type of sub-object that
  wants to delegate its validation to another validator taken from the factory.

The list of built-in validators is as follows.

* Validators for each profile (unless specified otherwise in the respective
  profiles) are all in package ``de.bund.bsi.tr_esor.checktool.validation.
  default_impl``

* AlgorithmUsageValidator
* ArchiveTimeStampChainValidator
* BaseValidator.java
* EvidenceRecordValidator.java
* ArchiveTimeStampSequenceValidator
* ArchiveTimeStampValidator.java
* DummyTimeStampValidator.java
* Validators for ERS basis profile (in sub-package ``basis.ers``

* BasisErsAlgorithmUsageValidator
* BasisErsDummyTimeStampValidator
* BasisErsArchiveTimeStampChainValidator
* BasisErsArchiveTimeStampSequenceValidator
* BasisErsEvidenceRecordValidator
* BasisErsArchiveTimeStampValidator

Furthermore, the application contains the classes

``de.bund.bsi.tr_esor.checktool.validation.default_impl.
ECardTimeStampValidator`` and

``de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.
BasisErsECardTimeStampValidator``

for online validation of time stamps (``org.bouncycastle.tsp.TimeStampToken``)
by calling an external eCard-API service, for instance Governikus SC. Those two
classes have to be declared in the configuration to be used.

More precisely, insert the following block into a ``Profile`` or into
``General/ConfiguredObjects``.

.. code-block:: xml

      <Validator>
        <className>
          de.bund.bsi.tr_esor.checktool.validation.default_impl.ECardTimeStampValidator
        </className>
        <parameter name="eCardURL">Insert URL here!</parameter>
        <targetType>org.bouncycastle.tsp.TimeStampToken</targetType>
      </Validator>

Both classes ECardTimeStampValidator and BasisErsECardTimeStampValidator
require only one parameter named ``eCardURL`` which contains the URL of the
WSDL of the eCardAPI web service. These validators have been tested with
Governikus SC as service provider.
