using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Ensues.Security.Cryptography {
    [TestFixture]
    public class PasswordAlgorithmTests {
        private class MockConstantTimeComparer : IEqualityComparer<string> {
            public Func<string, string, bool> EqualsProxy { get; set; }
            public bool Equals(string x, string y) {
                var p = EqualsProxy;
                if (p != null) return p(x, y);
                return default(bool);
            }
            public int GetHashCode(string obj) {
                throw new NotImplementedException();
            }
        }

        [SetUp]
        public void SetUp() {
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
        public void Compare_WorksForLongPasswords() {
            var password = Enumerable
                .Range(0, 100)
                .Select(_ => "abcdefghijklmnopqrstuvwxyz0123456789")
                .Aggregate((s1, s2) => s1 + s2 + "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            var algo = new PasswordAlgorithm();
            var computed = algo.Compute(password);
            Assert.IsTrue(algo.Compare(password, computed));
            var incorrectPassword = password.Remove(0, 1);
            Assert.IsFalse(algo.Compare(incorrectPassword, computed));
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

            var mock = new MockConstantTimeComparer { EqualsProxy = func };
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
        public void Compare_NullPasswordReturnsFalse() {
            var pa = new PasswordAlgorithm();
            var cr = pa.Compute("computed result");
            Assert.IsFalse(pa.Compare(null, cr));
        }

        [Test]
        public void Compare_EmptyPasswordDoesNotThrowException() {
            var pa = new PasswordAlgorithm();
            var cr = pa.Compute("password");
            var ex1 = default(Exception);
            try { 
                pa.Compare(string.Empty, cr); 
            }
            catch (Exception ex) { 
                ex1 = ex; 
            }
            Assert.IsNull(ex1);
        }

        [Test]
        public void Compare_ComputedResultThatWasNotComputedThrowsException() {
            var pa = new PasswordAlgorithm();
            var ex = default(Exception);
            try { 
                pa.Compare("plain text", "not computed"); 
            }
            catch (Exception e) { 
                ex = e; 
            }
            Assert.IsNotNull(ex);
        }

        [Test]
        public void Compare_NullComputedResultReturnsFalse() {
            var pa = new PasswordAlgorithm();
            Assert.IsFalse(pa.Compare("password", null));
        }

        [Test]
        public void Compare_NullParametersReturnsFalse() {
            var pa = new PasswordAlgorithm();
            Assert.IsFalse(pa.Compare(null, null));
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

            var mock = new MockConstantTimeComparer { EqualsProxy = func };
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

        [Test]
        public void ConstantTimeComparer_IsInstance() {
            var comparer = new PasswordAlgorithm().ConstantTimeComparer;
            Assert.IsNotNull(comparer);
            Assert.AreEqual(typeof(ConstantTimeComparer), comparer.GetType());
        }

        [Test]
        public void Compute_ComputesEmptyString() {
            var algo = new PasswordAlgorithm();
            var comp = algo.Compute("");
            Assert.IsFalse(string.IsNullOrWhiteSpace(comp));
        }

        [Test]
        public void Compare_ComparesComputedEmptyString() {
            var algo = new PasswordAlgorithm();
            var comp = algo.Compute("");
            Assert.IsTrue(algo.Compare("", comp));
        }

        [Test]
        public void Computed_ThrowsArgumentNullException() {
            var algo = new PasswordAlgorithm();
            var exception = default(ArgumentNullException);
            try {
                algo.Compute(null);
            }
            catch (ArgumentNullException ex) {
                exception = ex;
            }
            Assert.IsNotNull(exception);
            Assert.AreEqual("password", exception.ParamName);
        }

        [Test]
        public void Compute_SHA256Creates76CharacterComputation() {
            var algo = new PasswordAlgorithm();
            algo.HashFunction = HashFunction.SHA256;
            foreach (var password in new[] { "", "1234", "password", "asdf1234JKL:", "qwertyuiopasdfghjklzxcvbnm!@#$%^&*()\r\n\t " }) {
                var comp = algo.Compute(password);
                Assert.AreEqual(76, comp.Length);
                Assert.IsTrue(algo.Compare(password, comp));
            }
        }

        [Test]
        public void Compute_SHA384Creates96CharacterComputation() {
            var algo = new PasswordAlgorithm();
            algo.HashFunction = HashFunction.SHA384;
            foreach (var password in new[] { "", "1234", "password", "asdf1234JKL:", "qwertyuiopasdfghjklzxcvbnm!@#$%^&*()\r\n\t " }) {
                var comp = algo.Compute(password);
                Assert.AreEqual(96, comp.Length);
                Assert.IsTrue(algo.Compare(password, comp));
            }
        }

        [Test]
        public void Compute_SHA512Creates120CharacterComputation() {
            var algo = new PasswordAlgorithm();
            algo.HashFunction = HashFunction.SHA512;
            foreach (var password in new[] { "", "1234", "password", "asdf1234JKL:", "qwertyuiopasdfghjklzxcvbnm!@#$%^&*()\r\n\t " }) {
                var comp = algo.Compute(password);
                Assert.AreEqual(120, comp.Length);
                Assert.IsTrue(algo.Compare(password, comp));
            }
        }

        [Test]
        public void Compute_ThrowsExceptionIfHashFunctionIsInvalid() {
            var algo = new PasswordAlgorithm();
            var invalid = Enum.GetValues(typeof(HashFunction)).Cast<short>().Max() + 1;
            algo.HashFunction = (HashFunction)invalid;
            var exception = default(Exception);
            try {
                algo.Compute("password");
            }
            catch (Exception ex) {
                exception = ex;
            }
            Assert.IsNotNull(exception);
        }

        [Test]
        public void ConstantTimeComparer_IsDefault() {
            Assert.AreSame(ConstantTimeComparer.Default, new PasswordAlgorithm().ConstantTimeComparer);
        }

        [Test]
        public void VariableTimeComparer_IsOrdinal() {
            Assert.AreSame(StringComparer.Ordinal, new PasswordAlgorithm().VariableTimeComparer);
        }

        private static class VariableTimeComparer_UsedWhenCompareInConstantTimeIsFalse_Helper {
            public class VariableTimeComparer : IEqualityComparer<string> {
                public Func<string, string, bool> EqualsProxy { get; set; }
                public bool Equals(string x, string y) {
                    var p = EqualsProxy;
                    if (p != null) return p(x, y);
                    return default(bool);
                }
                public int GetHashCode(string obj) {
                    throw new NotSupportedException();
                }
            }
        }

        [Test]
        public void VariableTimeComparer_UsedWhenCompareInConstantTimeIsFalse() {
            var algo = new PasswordAlgorithm();
            var comparer = new VariableTimeComparer_UsedWhenCompareInConstantTimeIsFalse_Helper.VariableTimeComparer();
            algo.VariableTimeComparer = comparer;
            algo.CompareInConstantTime = false;
            var equal = false;
            var entered = 0;
            comparer.EqualsProxy = (x, y) => {
                entered++;
                return equal;
            };
            var password = "password";
            var computed = algo.Compute(password);
            equal = false;
            Assert.IsFalse(algo.Compare(password, computed));
            equal = true;
            Assert.IsTrue(algo.Compare(password, computed));
            Assert.AreEqual(2, entered);
        }
    }
}
