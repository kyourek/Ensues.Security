using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Ensues.Security.Cryptography.Tests {
    
    [TestClass]
    public class PasswordAlgorithmTests {
    
        [TestMethod]
        public void SaltLength_IsInitially16() {
            Assert.AreEqual(16, new PasswordAlgorithm().SaltLength);
        }

        [TestMethod]
        public void HashIterations_IsInitially1000() {
            Assert.AreEqual(1000, new PasswordAlgorithm().HashIterations);
        }

        [TestMethod]
        public void HashFunction_IsInitiallySHA256() {
            Assert.AreEqual(HashFunction.SHA256, new PasswordAlgorithm().HashFunction);
        }

        [TestMethod]
        public void Compare_ReturnsTrueForEqualPasswords() {

            var password = "A weak password!";

            var algo = new PasswordAlgorithm();
            var computed = algo.Compute(password);

            Assert.AreNotEqual(password, computed);
            Assert.IsTrue(algo.Compare(password, computed));
        }

        [TestMethod]
        public void Compare_WorksAfterHashIterationsIsChanged() {

            var password = "not much better";

            var algo = new PasswordAlgorithm();
            var computed = algo.Compute(password);

            algo.HashIterations = 999999;

            Assert.IsTrue(algo.Compare(password, computed));
        }

        [TestMethod]
        public void Compare_WorksAfterSaltLengthIsChanged() {

            var password = "This 1 is a stronger passw0rd.";

            var algo = new PasswordAlgorithm();
            var computed = algo.Compute(password);

            algo.SaltLength = 999999;

            Assert.IsTrue(algo.Compare(password, computed));
        }

        [TestMethod]
        public void Compare_ReturnsFalseForDifferentCase() {
            var algo = new PasswordAlgorithm();
            var computed = algo.Compute("different case");
            Assert.IsFalse(algo.Compare("different caSe", computed));
        }

        [TestMethod]
        public void Compare_ReturnsFalseForUnequalStringLengths() {
            var algo = new PasswordAlgorithm();
            var computed = algo.Compute("different length");
            Assert.IsFalse(algo.Compare("different length ", computed));
        }

        [TestMethod]
        public void CompareInConstantTime_IsInitiallyTrue() {
            Assert.IsTrue(new PasswordAlgorithm().CompareInConstantTime);
        }

        [TestMethod]
        public void CompareInConstantTime_CanBeSet() {
            var algo = new PasswordAlgorithm();
            foreach (var b in new[] { true, false, true }) {
                algo.CompareInConstantTime = b;
                Assert.AreEqual(b, algo.CompareInConstantTime);
            }
        }

        [TestMethod]
        public void HashFunction_CanBeSet() {
            var algo = new PasswordAlgorithm();
            var values = Enum.GetValues(typeof(HashFunction)).Cast<HashFunction>().ToList();
            Assert.AreNotEqual(0, values.Count());
            foreach (var value in values) {
                algo.HashFunction = value;
                Assert.AreEqual(value, algo.HashFunction);
            }
        }

        [TestMethod]
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

        [TestMethod]
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

        [TestMethod]
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

        [TestMethod]
        public void Compute_ComputesDifferentResultsForSamePassword() {
            var algo = new PasswordAlgorithm();
            var password = "asdfjkl;";

            var result1 = algo.Compute(password);
            var result2 = algo.Compute(password);

            Assert.AreNotEqual(result1, result2);
        }

        [TestMethod]
        public void SaltLength_0Works() {
            var algo = new PasswordAlgorithm();
            var password = "1234";

            algo.SaltLength = 0;
            var computedResult = algo.Compute(password);

            Assert.IsTrue(algo.Compare(password, computedResult));
        }

        [TestMethod]
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

        [TestMethod]
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
    }
}
