using System;
using System.IO;
using System.Linq;
using System.Text;

using NUnit.Framework;

using Ensues.Configuration;
namespace Ensues.Security.Cryptography.Tests {
    
    [TestFixture]
    public class PasswordAlgorithmTests {

        private class ConstantTimeComparerMock : ConstantTimeComparer {

            public Func<string, string, bool> OnEquals { get; set; }

            public override bool Equals(string x, string y) {
                return OnEquals(x, y);
            }
        }

        [Test]
        public void SaltLength_IsInitially16() {
            Assert.AreEqual(16, new PasswordAlgorithm().SaltLength);
        }

        [Test]
        public void HashIterations_IsInitially1000() {
            Assert.AreEqual(1000, new PasswordAlgorithm().HashIterations);
        }

        [Test]
        public void HashFunction_IsInitiallySHA256() {
            Assert.AreEqual(HashFunction.SHA256, new PasswordAlgorithm().HashFunction);
        }

        [Test]
        public void Compare_ReturnsTrueForEqualPasswords() {

            var password = "A weak password!";

            var algo = new PasswordAlgorithm();
            var computed = algo.Compute(password);

            Assert.AreNotEqual(password, computed);
            Assert.IsTrue(algo.Compare(password, computed));
        }

        [Test]
        public void Compare_WorksAfterHashIterationsIsChanged() {

            var password = "not much better";

            var algo = new PasswordAlgorithm();
            var computed = algo.Compute(password);

            algo.HashIterations = 999999;

            Assert.IsTrue(algo.Compare(password, computed));
        }

        [Test]
        public void Compare_WorksAfterSaltLengthIsChanged() {

            var password = "This 1 is a stronger passw0rd.";

            var algo = new PasswordAlgorithm { SaltLength = 8 };
            var computed = algo.Compute(password);

            algo.SaltLength = 88;
            Assert.IsTrue(algo.Compare(password, computed));
        }

        [Test]
        public void Compare_ReturnsFalseForDifferentCase() {
            var algo = new PasswordAlgorithm();
            var computed = algo.Compute("different case");
            Assert.IsFalse(algo.Compare("different caSe", computed));
        }

        [Test]
        public void Compare_ReturnsFalseForUnequalStringLengths() {
            var algo = new PasswordAlgorithm();
            var computed = algo.Compute("different length");
            Assert.IsFalse(algo.Compare("different length ", computed));
        }

        [Test]
        public void CompareInConstantTime_IsInitiallyTrue() {
            Assert.IsTrue(new PasswordAlgorithm().CompareInConstantTime);
        }

        [Test]
        public void CompareInConstantTime_CanBeSet() {
            var algo = new PasswordAlgorithm();
            foreach (var b in new[] { true, false, true }) {
                algo.CompareInConstantTime = b;
                Assert.AreEqual(b, algo.CompareInConstantTime);
            }
        }

        [Test]
        public void HashFunction_CanBeSet() {
            var algo = new PasswordAlgorithm();
            var values = Enum.GetValues(typeof(HashFunction)).Cast<HashFunction>().ToList();
            Assert.AreNotEqual(0, values.Count());
            foreach (var value in values) {
                algo.HashFunction = value;
                Assert.AreEqual(value, algo.HashFunction);
            }
        }

        [Test]
        public void Compare_WorksWithAllHashFunctions() {
            var algo = new PasswordAlgorithm();
            var computedResults = Enum.GetValues(typeof(HashFunction))
                .Cast<HashFunction>()
                .Select(hashFunction => {
                    algo.HashFunction = hashFunction;
                    return algo.Compute("Here's the password: ");
                });

            foreach (var computedResult in computedResults) {

                Assert.IsTrue(algo.Compare("Here's the password: ", computedResult));
                Assert.IsFalse(algo.Compare("here's the password: ", computedResult));
                Assert.IsFalse(algo.Compare("Here's the password:", computedResult));
            }
        }

        [Test]
        public void Compute_CreatesDifferentResultsWithDifferentHashFunctions() {
            var algo = new PasswordAlgorithm();
            var password = "1234";

            algo.HashFunction = HashFunction.SHA256;
            var sha256Result = algo.Compute(password);

            algo.HashFunction = HashFunction.SHA384;
            var sha384Result = algo.Compute(password);

            algo.HashFunction = HashFunction.SHA512;
            var sha512Result = algo.Compute(password);

            Assert.IsTrue(sha384Result.Length > sha256Result.Length);
            Assert.IsTrue(sha512Result.Length > sha384Result.Length);
        }

        [Test]
        public void HashIterations_ChangesComputedResult() {
            var algo = new PasswordAlgorithm();
            var password = "password";

            var results = Enumerable.Range(0, 10).Select(i => {
                algo.HashIterations = i;
                return algo.Compute(password);
            })
            .ToList();

            Assert.AreEqual(results.Count(), results.Distinct().Count());
        }

        [Test]
        public void Compute_ComputesDifferentResultsForSamePassword() {
            var algo = new PasswordAlgorithm();
            var password = "asdfjkl;";

            var result1 = algo.Compute(password);
            var result2 = algo.Compute(password);

            Assert.AreNotEqual(result1, result2);
        }

        [Test]
        public void SaltLength_0Works() {
            var algo = new PasswordAlgorithm();
            var password = "1234";

            algo.SaltLength = 0;
            var computedResult = algo.Compute(password);

            Assert.IsTrue(algo.Compare(password, computedResult));
        }

        [Test]
        public void SaltLength_ThrowsExceptionIfLessThan0() {
            var algo = new PasswordAlgorithm();

            try {
                algo.SaltLength = -1;
                Assert.Fail();
            }
            catch (ArgumentOutOfRangeException ex) {
                Assert.AreEqual("SaltLength", ex.ParamName);
            }
        }

        [Test]
        public void HashIterations_ThrowsExceptionIfLessThan0() {
            var algo = new PasswordAlgorithm();

            try {
                algo.HashIterations = -1;
                Assert.Fail();
            }
            catch (ArgumentOutOfRangeException ex) {
                Assert.AreEqual("HashIterations", ex.ParamName);
            }
        }

        [Test]
        public void Compare_UsesConstantTimeComparer() {
            var retv = default(bool);
            var xstr = default(string);
            var ystr = default(string);
            var func = new Func<string, string, bool>((x, y) => {
                xstr = x;
                ystr = y;
                return retv;
            });

            var mock = new ConstantTimeComparerMock { OnEquals = func };
            var algo = new PasswordAlgorithm { 
                ConstantTimeComparer = mock,
                CompareInConstantTime = true
            };

            foreach (var v in new[] { true, false }) {

                retv = v;

                var password = "password " + retv;
                var computed = algo.Compute(password);

                Assert.AreEqual(retv, algo.Compare(password, computed));
                Assert.AreEqual(computed, xstr);
                Assert.AreEqual(computed, ystr);
            }
        }

        [Test]
        public void Compute_NullThrowsException() {            
            var ex = default(Exception);
            var pa = new PasswordAlgorithm();
            
            try {
                pa.Compute(null);
            }
            catch (Exception e) {
                ex = e;
            }

            Assert.IsNotNull(ex);
        }

        [Test]
        public void Compute_EmptyStringDoesNotThrowException() {
            var ex = default(Exception);
            var pa = new PasswordAlgorithm();
            try { pa.Compute(string.Empty); }
            catch (Exception e) { ex = e; }
            Assert.IsNull(ex);
        }

        [Test]
        public void Compare_NullPasswordThrowsException() {
            var pa = new PasswordAlgorithm();
            var cr = pa.Compute("computed result");

            var ex1 = default(Exception);
            try { pa.Compare(null, cr); }
            catch (Exception ex) { ex1 = ex; }
            Assert.IsNotNull(ex1);
        }

        [Test]
        public void Compare_EmptyPasswordDoesNotThrowException() {
            var pa = new PasswordAlgorithm();
            var cr = pa.Compute("password");

            var ex1 = default(Exception);
            try { pa.Compare(string.Empty, cr); }
            catch (Exception ex) { ex1 = ex; }
            Assert.IsNull(ex1);
        }

        [Test]
        public void Compare_ComputedResultThatWasNotComputedThrowsException() {
            var pa = new PasswordAlgorithm();
            var ex = default(Exception);
            try { pa.Compare("plain text", "not computed"); }
            catch (Exception e) { ex = e; }
            Assert.IsNotNull(ex);
        }

        [Test]
        public void Compare_NullComputedResultThrowsException() {
            var pa = new PasswordAlgorithm();
            var ex1 = default(Exception);
            try { pa.Compare("password", null); }
            catch (Exception ex) { ex1 = ex; }
            Assert.IsNotNull(ex1);
        }

        [Test]
        public void Compare_NullParametersThrowsException() {
            var pa = new PasswordAlgorithm();
            var ex1 = default(Exception);
            try { pa.Compare(null, null); }
            catch (Exception ex) { ex1 = ex; }
            Assert.IsNotNull(ex1);
        }

        [Test]
        public void Compare_DoesNotUseConstantTimeComparer() {
            var retv = default(bool);
            var xstr = default(string);
            var ystr = default(string);
            var func = new Func<string, string, bool>((x, y) => {
                xstr = x;
                ystr = y;
                return retv;
            });

            var mock = new ConstantTimeComparerMock { OnEquals = func };
            var algo = new PasswordAlgorithm {
                ConstantTimeComparer = mock,
                CompareInConstantTime = false
            };

            var password = "pass";
            var computed = algo.Compute(password);

            retv = false;

            Assert.IsTrue(algo.Compare(password, computed));

            Assert.IsNull(xstr);
            Assert.IsNull(ystr);
        }

        [Test]
        public void Example_DoesNotThrowException() {
            try {
                var pa = new PasswordAlgorithm();

                var computedResult_1 = pa.Compute("my password");
                pa.Compare("my password", computedResult_1);             // Returns true.

                pa.SaltLength = 64;
                pa.HashFunction = HashFunction.SHA512;
                pa.HashIterations = 10000;

                var computedResult_2 = pa.Compute("another password");   // Creates an encoded password hash using a
                                                                         // longer salt, a stronger hash function, and
                                                                         // more key-stretching iterations than before.

                pa.Compare("my password", computedResult_1);             // Still returns true, because the previous
                                                                         // salt length, hash function, and key-stretching
                                                                         // iterations are stored in computedResult_1.
            }
            catch {
                Assert.Fail();
            }
        }

//        [Test]
//        public void Constructor_SetsPropertiesBasedOnConfiguration() {
//            var appConfigFile = Path.GetTempFileName();
//            var appConfig = @"<?xml version='1.0'?>
//                <configuration>
//                    <configSections>
//                        <section name='ensues.security' type='Ensues.Configuration.SecuritySection, Ensues.Security' />
//                    </configSections>
//                    <ensues.security>
//                        <passwordAlgorithm hashFunction='SHA384' hashIterations='654321' compareInConstantTime='false' saltLength='432' />
//                    </ensues.security>
//                </configuration>
//            ";

//            File.WriteAllText(appConfigFile, appConfig);

//            try {
//                using (AppConfig.Change(appConfigFile)) {
//                    var pa = new PasswordAlgorithm();
//                    Assert.AreEqual(HashFunction.SHA384, pa.HashFunction);
//                    Assert.AreEqual(654321, pa.HashIterations);
//                    Assert.AreEqual(false, pa.CompareInConstantTime);
//                    Assert.AreEqual(432, pa.SaltLength);
//                }
//            }
//            finally {
//                File.Delete(appConfigFile);
//            }
//        }
    }
}
