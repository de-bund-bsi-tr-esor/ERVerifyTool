Creating an additional validator
================================

You may extend the verification logic of the application by writing own classes
for verifying certain objects.

As an example, the application already contains two validator classes for
validating RFC 3161 time stamps, namely one which calls an external application
to do online verifications of time stamp certificates and a
``DummyTimeStampValidator``, which does not require any online connection.
The ``DummyTimeStampValidator`` is the default. It is used to validate
timestamps unless some other validator is specified.

To activate the eCard base timestamp validator, include the following tag into
the ``General/ConfiguredObjects`` section of your configuration:

.. code-block:: xml

      <Validator>
        <className>
          de.bund.bsi.tr_esor.checktool.validation.default_impl.ECardTimeStampValidator
        </className>
        <parameter name="eCardURL">Insert URL here!</parameter>
        <targetType>org.bouncycastle.tsp.TimeStampToken</targetType>
      </Validator>

See appendix for the list of built-in validators and respective target classes.

How the application chooses validators
--------------------------------------

Whenever a certain parsed object is to be validated, an appropriate validator
object is requested from the ``ValidatorFactory``. That factory knows the
verification profile of the current context. First, it looks for validators
which are mentioned in the respective ``Profile`` section of the configuration.
If that section contains more than one validator with a matching target class
(which may be some base class or interface of the object we are about to
validate), it chooses the most direct one. If the profile section of the
configuration does not contain a matching validator, then the
``General/ConfiguredObjects`` section is searched in the same way. If still no
suitable validator is found, the factory uses the same rules for selecting one
of the built-in validators.

Furthermore, every call to the ``ValidatorFactory.getValidator`` method must
provide a ``ValidationContext`` object and may request a validator which
creates a certain type of report. The factory restricts its search to all
validators which can work with the given context and can create the requested
report type.


Writing the Validator
---------------------

Use the SDK to provide the necessary classes in your class path. The provided
libraries contain the whole ERVerifyTool. Access is provided to all existing
classes to call or inherit. The API documentation is available as appendix in
this document or in HTML format in the directory ``sdk/apidocs``.

Interface and base class
^^^^^^^^^^^^^^^^^^^^^^^^

Write a class implementing the interface ``de.bund.bsi.tr_esor.checktool.
validation.Validator``. Closely follow the requirements within the API
documentation of each respective interface or base class. In general, you
should consider extending the class

``de.bund.bsi.tr_esor.checktool.validation.default_impl.BaseValidator``

which provides some basic checks to ensure that validation parameters and
context match. The validator must have a constructor without parameters or one
with a single parameter of type ``java.util.Map<java.lang.String,
java.lang.String>``.

The ``validate`` or ``validateInternal`` method is given the parameters:

* ``ref`` - a unique reference to identify the checked object
* ``toBeChecked`` - the object itself

That method should validate the object and return an instance of

``de.bund.bsi.tr_esor.checktool.validation.report.ReportPart``

which contains the validation results.

The ``Validator`` interface is a generic class with type parameters

* type of object to validate
* type of ``ValidationContext`` that class can work with. If you do not have
  any requirements to that context, specify the type ``ValidationContext``
  itself.
* type of ``ReportPart`` created by the validator.

It is strongly recommended to validate only one level of object in a validator
and delegate validation of sub-objects to other special validators. To obtain
further validator instances, always call the

``de.bund.bsi.tr_esor.checktool.validation.ValidatorFactory.getValidator``

method specifying class of object to validate, class of report part to create
and current context.

As an example, see class

``de.bund.bsi.tr_esor.checktool.validation.default_impl.
ECardTimeStampValidator``.

During the validation, the validator may assume that the method
``setValidationContext`` has been called previously. Thus, information from
validating other parts of an object tree usually is available. Currently, the
application only uses ``ValidationContext`` objects of class

``de.bund.bsi.tr_esor.checktool.validation.ErValidationContext``

which contains for instance information about which hash values must be
covered.

The validation context
^^^^^^^^^^^^^^^^^^^^^^

During validating a more complex object like an evidence record, certain
``Validator`` objects may need access to data or validation results regarding
other parts of the object structure. This data is collected in an object called
validation context, which is available throughout validation of the whole
structure to all validators. Each validator must specify which kind of
``ValidationContext`` it can work with.

When calling another validator from within a validator, normally the current
context is passed.

The reference
^^^^^^^^^^^^^

All validated objects within an object tree are addressed by an instance of

``de.bund.bsi.tr_esor.checktool.validation.report.Reference``.

The references contain at least a human-readable field name, which is useful
for debugging purposes. Furthermore, the reference may contain other
information to be used in XML verification reports. When calling the validation
of some sub-object, you should create an own reference for that object by
calling ``Reference.newChild(String)``.


Parameter and return types of validation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Objects which are passed as parameter ``toCheck`` to a ``Validator.validate``
method will have one of the types listed in appendix "Internal data types" or
may have an additional type if

* the application is extended to validate other given objects, for instance to
  create XAIP reports
* an added validator encounters another object within the object it is
  validating and decides to delegate the validation of that sub-object.

All existing subclasses of
``de.bund.bsi.tr_esor.checktool.validation.report.ReportPart``
are supported by the generator for the XML verification report. If you decide
to write your own ``ReportPart`` class, you should let it implement

``de.bund.bsi.tr_esor.checktool.validation.report.OutputCreator<T>``.

Because an XML verification report is currently the only supported output type,
it is always possible to satisfy the needs of output creation by implementing
``OutputCreator<IndivudualReportType>``.

Adding your new validator
^^^^^^^^^^^^^^^^^^^^^^^^^

Depending on whether your validator is specific to a certain profile or usable
with all supported profiles, declare the new validator in the respective
section ``Profile`` or in section ``General/ConfiguredObjects``. Within the
``Validator`` tag, you have to specify

* the fully qualified name of the validator class
* the fully qualified name of the data class it can validate
* in case it requires construction parameters (Map), all entries for that
  parameter map

Add the new validator class to the class path and start the command line
application providing the parameter ``-conf <filename>`` only. The application
will check whether the configuration has correct format and all validators can
be created properly.
