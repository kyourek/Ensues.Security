using System;
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
    }
}
