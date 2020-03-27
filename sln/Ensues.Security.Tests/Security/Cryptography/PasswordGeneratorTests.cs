using NUnit.Framework;
using System;
using System.Linq;

namespace Ensues.Security.Cryptography {
    [TestFixture]
    public class PasswordGeneratorTests {
        [SetUp]
        public void SetUp() {
        }

        [Test]
        public void Generate_GeneratesString() {
            var gen = new PasswordGenerator();
            var pass = gen.Generate();
            Assert.IsNotNull(pass);
            Assert.AreNotEqual("", pass);
        }

        [Test]
        public void Generate_Generates10CharacterPassword() {
            var gen = new PasswordGenerator();
            var pass = gen.Generate();
            Assert.AreEqual(10, pass.Length);
        }

        [Test]
        public void Generate_GeneratesPasswordWithLettersAndNumbers() {
            var gen = new PasswordGenerator();
            for (var i = 0; i < 10; i++) {
                var pass = gen.Generate();
                Assert.IsTrue(pass.All(c => char.IsLetterOrDigit(c)));
            }
        }

        [Test]
        public void Length_DefaultIs10() {
            Assert.AreEqual(10, new PasswordGenerator().Length);
        }

        [Test]
        public void Generate_GeneratesPasswordWithLength() {
            var gen = new PasswordGenerator();
            foreach (var i in new[] { 0, 1, 5, 50, 500 }) {
                gen.Length = i;
                var pass = gen.Generate();
                Assert.AreEqual(i, pass.Length);
            }
        }

        [Test]
        public void Length_LessThanZeroThrowsException() {
            var gen = new PasswordGenerator();
            foreach (var i in new[] { -1, -5, -50 }) {
                var exception = default(ArgumentOutOfRangeException);
                try {
                    gen.Length = i;
                }
                catch (ArgumentOutOfRangeException ex) {
                    exception = ex;
                }
                Assert.IsNotNull(exception);
                Assert.AreEqual("Length", exception.ParamName);
                Assert.AreEqual(i, exception.ActualValue);
            }
        }

        [Test]
        public void Symbols_NullThrowsException() {
            var gen = new PasswordGenerator();
            var exception = default(ArgumentNullException);
            try {
                gen.Symbols = null;
            }
            catch (ArgumentNullException ex) {
                exception = ex;
            }
            Assert.AreEqual("Symbols", exception.ParamName);
        }

        [Test]
        public void Symbols_ContainsAllDigitsAndLetters() {
            var gen = new PasswordGenerator();
            var sym = gen.Symbols;
            var lower = "abcdefghijklmnopqrstuvwxyz";
            var upper = lower.ToUpperInvariant();
            var digits = "0123456789";
            var all = lower + upper + digits;
            Assert.AreEqual(all.Length, sym.Length);
            Assert.IsTrue(all.All(c => sym.Contains(c)));
        }

        [Test]
        public void Generate_GeneratesPasswordWithSymbols() {
            var gen = new PasswordGenerator();
            gen.Symbols = "?$%";
            var pass = gen.Generate();
            Assert.IsTrue(pass.All(c => "?$%".Contains(c)));
        }

        [Test]
        public void Symbols_EmptyStringThrowsException() {
            var gen = new PasswordGenerator();
            var exception = default(ArgumentException);
            try {
                gen.Symbols = "";
            }
            catch (ArgumentException ex) {
                exception = ex;
            }
            Assert.IsNotNull(exception);
            Assert.AreEqual("Symbols", exception.ParamName);
        }

        [Test]
        public void Generate_GeneratesWithOneSymbol() {
            var gen = new PasswordGenerator();
            gen.Symbols = "1";
            gen.Length = 50;
            var pass = gen.Generate();
            var expected = new string(Enumerable.Range(0, 50).Select(_ => '1').ToArray());
            Assert.AreEqual(expected, pass);
        }

        [Test]
        public void Generate_GeneratesEmptyPassword() {
            var gen = new PasswordGenerator { Length = 0 };
            Assert.AreEqual("", gen.Generate());
        }

        [Test]
        public void Generate_GeneratesRandomPassword() {
            var gen = new PasswordGenerator();
            var passwords = Enumerable.Range(0, 1000).Select(_ => gen.Generate()).ToList();
            Assert.AreEqual(1000, passwords.Distinct().Count());
        }
    }
}
