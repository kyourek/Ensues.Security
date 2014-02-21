Ensues.Security
===================

**Password algorithm for .NET**

**Ensues.Security** contains a password algorithm that allows new passwords to be made more robust while not affecting old passwords.

`PasswordAlgorithm` defaults to using the SHA-256 `HashAlgorithm` and 1000 key-stretching iterations. If requirements change, the `HashAlgorithm` and number of key-stretching iterations can change without having to alter previously created passwords or use a database schema. This is possible because information about how the password hash was created is stored in the encoded password itself.

**Ensues.Security** uses [NUnit][1] for unit tests.

Usage
===================

    var pa = new PasswordAlgorithm();

    var computedResult_1 = pa.Compute("my password");
    pa.Compare("my password", computedResult_1);                // Returns true.

    pa.SaltLength = 64;
    pa.HashFunction = HashFunction.SHA512;
    pa.HashIterations = 10000;

    var computedResult_2 = pa.Compute("another password");      // Creates an encoded password hash using a
                                                                // longer salt, a stronger hash function, and
                                                                // more key-stretching iterations than before.

    pa.Compare("my password", computedResult_1);                // Still returns true, because the previous
                                                                // salt length, hash function, and key-stretching
                                                                // iterations are stored in computedResult_1.

  [1]: http://www.nunit.org/ "NUnit"
